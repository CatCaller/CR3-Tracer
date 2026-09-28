// cr3logger.cpp - CR3-switch logger with real process resolution for baykus.
//
// Links directly against MemProcFS's native vmm.so C API (VMMDLL_*) - no
// Python involved at all. See README.md in the parent directory for why the
// earlier Python version existed and why it's gone.
//
// -disable-python is still passed to VMMDLL_Initialize(). This is NOT a
// language-specific workaround: vmm.so's own PluginManager_Initialize()
// (pluginmanager.c) unconditionally calls PluginManager_Initialize_Python()
// unless H->cfg.fDisablePython is set - gated identically for every caller,
// C++ included. On this host that embedded-Python forensic-plugin bootstrap
// segfaults inside libpython (confirmed with gdb: crash is in
// VmmPyPlugin_PythonInitializeEmbedded -> Util_PyAddSysPath -> PySys_GetObject,
// all inside vmm.so/vmmpyc.so's own code, not anything we call). We don't use
// forensic .py plugins, so skipping that subsystem is correct regardless.
//
// Unresolvable CR3s: MemProcFS's process enumeration exposes exactly two DTB
// fields per process (paDTB, paDTB_UserOpt - confirmed from vmmdll.h, this is
// the complete set, not a partial binding). A CR3 that still doesn't match
// anything after a forced refresh and several retries is a real page table
// VBS/Secure Kernel isolation is the common cause on a stock Windows 11 box.
// Per request: such events are silently dropped, never shown as a placeholder.

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern "C" {
#include "vmmdll.h"
}

namespace {

// ---------------------------------------------------------------------------
// Kernel interface (must match arch/x86/kvm/svm/cr3_trace.h exactly)
// ---------------------------------------------------------------------------

struct KvmCr3Event {
    std::uint64_t ns;
    std::uint32_t vcpu_id;
    std::uint32_t pad;
    std::uint64_t old_cr3;
    std::uint64_t new_cr3;
};
static_assert(sizeof(KvmCr3Event) == 32, "kvm_cr3_event layout must be 32 bytes");

constexpr const char* kDefaultDevice = "/dev/kvm_cr3trace";

constexpr unsigned long ioEncode(unsigned type, unsigned nr) {
    return (type << 8) | nr;
}
constexpr unsigned long kIocArm = ioEncode(0xC3, 1);
constexpr unsigned long kIocDisarm = ioEncode(0xC3, 2);
constexpr unsigned long kIocFlush = ioEncode(0xC3, 3);

// CR3 bits 0-11 may carry a PCID; bit 63 is the "no-TLB-flush" MOV-CR3 hint.
// Neither is part of the physical page-table-root address.
constexpr std::uint64_t kCr3PhysMask = 0x0000'FFFF'FFFF'F000ULL;
constexpr std::uint64_t phys(std::uint64_t cr3) {
    return cr3 & kCr3PhysMask;
}

// ---------------------------------------------------------------------------
// Terminal colour helpers
// ---------------------------------------------------------------------------

bool g_color = true;
constexpr const char* kReset = "\033[0m";
constexpr const char* kDim = "\033[2m";
constexpr const char* kCyan = "\033[36m";
constexpr const char* kYellow = "\033[33m";
constexpr const char* kGreen = "\033[32m";
constexpr const char* kRed = "\033[31m";
constexpr const char* kMagenta = "\033[35m";

std::string col(const char* code, const std::string& s) {
    if (!g_color) {
        return s;
    }
    return std::string(code) + s + kReset;
}

std::string fmtCr3(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(v));
    return buf;
}

std::string padRight(std::string s, size_t width) {
    if (s.size() < width) {
        s.append(width - s.size(), ' ');
    }
    return s;
}

// ---------------------------------------------------------------------------
// MemProcFS session wrapper
// ---------------------------------------------------------------------------

struct ProcInfo {
    DWORD pid = 0;
    std::string name;
    ULONG64 dtb = 0;
    ULONG64 dtbUser = 0;
};

constexpr ULONG64 kOptRefreshAll = 0x2001ffff00000000ULL;

class VmmSession {
  public:
    ~VmmSession() {
        if (hVmm_) {
            VMMDLL_Close(hVmm_);
        }
    }

    bool init(const std::string& qemuDeviceArg) {
        std::string deviceOpt = "-device";
        std::vector<const char*> argv = {
            "-disable-python",
            deviceOpt.c_str(),
            qemuDeviceArg.c_str(),
        };

        hVmm_ = VMMDLL_Initialize(static_cast<DWORD>(argv.size()), argv.data());
        return hVmm_ != nullptr;
    }

    // Force MemProcFS to refresh its internal process cache right now.
    void refreshAll() {
        if (hVmm_) {
            VMMDLL_ConfigSet(hVmm_, kOptRefreshAll, 1);
        }
    }

    // Snapshot every currently-known process. Expensive-ish (a few ms to tens
    // of ms depending on process count); callers should cache the result.
    std::vector<ProcInfo> processList() {
        std::vector<ProcInfo> out;
        if (!hVmm_) {
            return out;
        }

        PVMMDLL_PROCESS_INFORMATION pInfos = nullptr;
        DWORD cInfos = 0;
        if (!VMMDLL_ProcessGetInformationAll(hVmm_, &pInfos, &cInfos) || !pInfos) {
            return out;
        }

        out.reserve(cInfos);
        for (DWORD i = 0; i < cInfos; ++i) {
            const VMMDLL_PROCESS_INFORMATION& pi = pInfos[i];

            ProcInfo p;
            p.pid = pi.dwPID;
            p.name = std::string(pi.szNameLong[0] ? pi.szNameLong : pi.szName);
            p.dtb = pi.paDTB;
            p.dtbUser = pi.paDTB_UserOpt;

            out.push_back(std::move(p));
        }

        VMMDLL_MemFree(pInfos);
        return out;
    }

  private:
    VMM_HANDLE hVmm_ = nullptr;
};

// ---------------------------------------------------------------------------
// CR3 -> process resolver. Retries against a fresh process list a bounded
// number of times; never fabricates a placeholder for something it can't
// find - the caller just won't get an entry for that CR3.
// ---------------------------------------------------------------------------

class Resolver {
  public:
    explicit Resolver(VmmSession& vmm) : vmm_(vmm) {
        rebuildIndex();
    }

    // Returns the owning process if resolvable (now, or after forcing a
    // refresh), std::nullopt otherwise.
    std::optional<ProcInfo> resolve(std::uint64_t cr3PhysKey) {
        if (auto it = byDtb_.find(cr3PhysKey); it != byDtb_.end()) {
            return it->second;
        }

        // Not found in the current snapshot - it might just be stale.
        maybeRefresh(/*force=*/true);
        if (auto it = byDtb_.find(cr3PhysKey); it != byDtb_.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    // Cheap periodic refresh so long-lived state (e.g. shuffle detection,
    // --new-only) stays accurate without a forced refresh on every miss.
    void tick() {
        maybeRefresh(/*force=*/false);
    }

  private:
    void maybeRefresh(bool force) {
        auto now = std::chrono::steady_clock::now();
        if (!force && now - lastRefresh_ < std::chrono::seconds(2)) {
            return;
        }

        lastRefresh_ = now;
        vmm_.refreshAll();
        rebuildIndex();
    }

    void rebuildIndex() {
        byDtb_.clear();
        for (auto& p : vmm_.processList()) {
            byDtb_[phys(p.dtb)] = p;

            if (p.dtbUser) {
                byDtb_[phys(p.dtbUser)] = p;
            }
        }
    }

    VmmSession& vmm_;
    std::unordered_map<std::uint64_t, ProcInfo> byDtb_;
    std::chrono::steady_clock::time_point lastRefresh_{};
};

// ---------------------------------------------------------------------------
// --pid / --name targeting
//
// Matches against a *live* resolution of each event's own CR3 (via Resolver,
// which already does forced-refresh-on-miss), not a periodically-polled
// snapshot of "the target's known DTBs". That distinction matters a lot here:
// a static snapshot can only match DTBs it already knew about, so the very
// moment a targeted process's CR3 changes (a shuffle - exactly the thing
// worth watching for) would fall outside the snapshot and get silently
// dropped instead of flagged. Resolving live means a shuffle is caught on
// the same event that produced it, and a process relaunched under a new PID
// (--name mode) is picked up immediately without any special-casing.
// ---------------------------------------------------------------------------

struct TargetFilter {
    std::optional<DWORD> pid;
    std::optional<std::string> nameLower;

    bool active() const {
        return pid.has_value() || nameLower.has_value();
    }

    bool matches(const ProcInfo& p) const {
        if (pid) {
            return p.pid == *pid;
        }

        std::string lower = p.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower.find(*nameLower) != std::string::npos;
    }
};

// ---------------------------------------------------------------------------
// QEMU PID auto-detection - by /proc inspection, not pgrep -f (which matches
// on ANY process's full cmdline, including unrelated ones whose paths happen
// to contain both "qemu" and the VM name, e.g. swtpm's socket path).
// ---------------------------------------------------------------------------

std::optional<pid_t> findQemuPid(const std::string& vmName) {
    const std::string needle = "guest=" + vmName;
    DIR* proc = opendir("/proc");
    if (!proc) {
        return std::nullopt;
    }

    std::optional<pid_t> result;
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        std::string name = entry->d_name;
        if (name.empty() || !std::isdigit(static_cast<unsigned char>(name[0]))) {
            continue;
        }

        pid_t pid = std::stoi(name);

        std::ifstream commFile("/proc/" + name + "/comm");
        std::string comm;
        std::getline(commFile, comm);
        if (comm.rfind("qemu-system", 0) != 0) {
            continue;
        }

        std::ifstream cmdlineFile("/proc/" + name + "/cmdline", std::ios::binary);
        std::stringstream buf;
        buf << cmdlineFile.rdbuf();
        std::string cmdline = buf.str();
        if (cmdline.find(needle) != std::string::npos) {
            result = pid;
            break;
        }
    }

    closedir(proc);
    return result;
}

// ---------------------------------------------------------------------------
// CLI options
// ---------------------------------------------------------------------------

struct Options {
    std::string device = kDefaultDevice;
    std::string vmName = "baykus";
    std::optional<pid_t> qemuPid;
    std::string qmpSocket = "/tmp/qmp-baykus.sock";
    std::optional<DWORD> targetPid;
    std::optional<std::string> targetName;
    bool noColor = false;
    bool showIdleReturn = false;
    int coalesceMs = 250;
    bool newOnly = false;
    bool showUnresolved = false;
    int shadowWindowMs = 50;
    long count = 0;
};

void printUsage(const char* prog) {
    std::cerr
        << "Usage: " << prog
        << " [OPTIONS]\n"
           "  --device FILE        /dev/kvm_cr3trace path (default: "
        << kDefaultDevice
        << ")\n"
           "  --vm-name NAME        libvirt guest name (default: baykus)\n"
           "  --qemu-pid PID        QEMU PID (auto-detected if omitted)\n"
           "  --qmp-socket PATH     QMP socket path (default: /tmp/qmp-baykus.sock)\n"
           "  --pid PID             only show switches involving this PID (must already be "
           "running)\n"
           "  --name SUBSTRING      only show switches involving processes whose name contains "
           "this\n"
           "                        (case-insensitive); waits for it to start if not running yet\n"
           "  --no-color            disable colored output\n"
           "  --show-idle-return    also show the bounce back to System/idle after each switch\n"
           "  --coalesce-ms N       collapse repeats of the same PID within N ms (default 250, "
           "0=off)\n"
           "  --new-only            show each distinct CR3 only the first time it's ever seen\n"
           "  --show-unresolved     with --pid/--name: also show CR3s that never resolve to any\n"
           "                        known process, IF they occur on a vCPU that just ran the "
           "target -\n"
           "                        catches a separate/hidden page table used briefly by the same\n"
           "                        thread (never linked into the normal process list, so normal\n"
           "                        resolution can't find it no matter how much it retries)\n"
           "  --shadow-window-ms N  how recently the target must have run on a vCPU for an "
           "unresolved\n"
           "                        CR3 there to count as correlated (default 50ms). Wider windows "
           "catch\n"
           "                        more but risk false positives from unrelated threads sharing "
           "that\n"
           "                        vCPU - Windows reschedules constantly, so seconds-wide windows "
           "are\n"
           "                        mostly coincidence, not causation.\n"
           "  -n, --count N         stop after N matching events (default: run forever)\n"
           "  -h, --help            this message\n";
}

std::optional<Options> parseArgs(int argc, char** argv) {
    Options o;
    static struct option long_opts[] = {
        {"device", required_argument, nullptr, 1},
        {"vm-name", required_argument, nullptr, 2},
        {"qemu-pid", required_argument, nullptr, 3},
        {"qmp-socket", required_argument, nullptr, 4},
        {"pid", required_argument, nullptr, 5},
        {"name", required_argument, nullptr, 6},
        {"no-color", no_argument, nullptr, 7},
        {"show-idle-return", no_argument, nullptr, 8},
        {"coalesce-ms", required_argument, nullptr, 9},
        {"new-only", no_argument, nullptr, 10},
        {"show-unresolved", no_argument, nullptr, 11},
        {"shadow-window-ms", required_argument, nullptr, 12},
        {"count", required_argument, nullptr, 'n'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    int c;
    while ((c = getopt_long(argc, argv, "n:h", long_opts, nullptr)) != -1) {
        switch (c) {
        case 1:
            o.device = optarg;
            break;
        case 2:
            o.vmName = optarg;
            break;
        case 3:
            o.qemuPid = std::stoi(optarg);
            break;
        case 4:
            o.qmpSocket = optarg;
            break;
        case 5:
            o.targetPid = static_cast<DWORD>(std::stoul(optarg));
            break;
        case 6:
            o.targetName = optarg;
            break;
        case 7:
            o.noColor = true;
            break;
        case 8:
            o.showIdleReturn = true;
            break;
        case 9:
            o.coalesceMs = std::stoi(optarg);
            break;
        case 10:
            o.newOnly = true;
            break;
        case 11:
            o.showUnresolved = true;
            break;
        case 12:
            o.shadowWindowMs = std::stoi(optarg);
            break;
        case 'n':
            o.count = std::stol(optarg);
            break;
        case 'h':
            printUsage(argv[0]);
            return std::nullopt;
        default:
            printUsage(argv[0]);
            return std::nullopt;
        }
    }

    if (o.targetPid && o.targetName) {
        std::cerr << "error: --pid and --name are mutually exclusive\n";
        return std::nullopt;
    }

    return o;
}

// ---------------------------------------------------------------------------
// Device I/O
// ---------------------------------------------------------------------------

std::atomic<int> g_deviceFd{-1};
std::atomic<bool> g_stop{false};

void handleSignal(int) {
    g_stop = true;
}

void disarmAndClose() {
    int fd = g_deviceFd.exchange(-1);
    if (fd >= 0) {
        ioctl(fd, kIocDisarm);
        close(fd);
    }
}

} // namespace

int main(int argc, char** argv) {
    auto optsOrNull = parseArgs(argc, argv);
    if (!optsOrNull) {
        return 1;
    }
    Options opts = *optsOrNull;
    g_color = !opts.noColor;

    bool wantTarget = opts.targetPid.has_value() || opts.targetName.has_value();

    if (!opts.qemuPid) {
        opts.qemuPid = findQemuPid(opts.vmName);

        if (!opts.qemuPid) {
            std::cerr << col(kYellow,
                             "[cr3logger] no running qemu-system process found for guest '"
                                 + opts.vmName + "'")
                      << "\n";
            return 1;
        }
    }

    std::cerr << col(kDim,
                     "[cr3logger] connecting to QEMU (PID "
                         + std::to_string(*opts.qemuPid) + ")...")
              << "\n";

    VmmSession vmm;
    std::string deviceArg =
        "qemu://hugepage-pid=" + std::to_string(*opts.qemuPid) + ",qmp=" + opts.qmpSocket;

    if (!vmm.init(deviceArg)) {
        std::cerr << col(kRed, "[cr3logger] failed to connect to QEMU instance") << "\n";
        return 1;
    }

    std::cerr << col(kGreen, "[cr3logger] vmmpyc-free native MemProcFS session initialized")
              << "\n";

    Resolver resolver(vmm);
    TargetFilter filter;
    filter.pid = opts.targetPid;
    if (opts.targetName) {
        std::string lower = *opts.targetName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        filter.nameLower = lower;
    }

    if (wantTarget) {
        std::string who = opts.targetName ? *opts.targetName : std::to_string(*opts.targetPid);
        std::cerr << col(
            kYellow,
            "[cr3logger] watching for process matching '" + who
                + "' (prints once matched; picks up shuffles and relaunches automatically)")
                  << "\n";
    }
    DWORD announcedPid = 0; // last PID we printed a "tracking" line for, to avoid repeating it

    int fd = open(opts.device.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "error: cannot open " << opts.device
                  << " - is the cr3-tracer kvm_amd.ko loaded? (try sudo)\n";
        return 1;
    }
    g_deviceFd = fd;

    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);

    ioctl(fd, kIocFlush);
    ioctl(fd, kIocArm);

    std::cerr << col(kGreen, "[cr3logger] armed, reading from " + opts.device + " (Ctrl+C to stop)")
              << "\n";

    const std::string header = padRight("TIME", 13) + padRight("VCPU", 7)
        + padRight("PID", 9) + padRight("PROCESS", 21)
        + padRight("OLD CR3", 19) + "NEW CR3";
    std::cout << col(kDim, header)
              << "\n";

    // pid -> set of phys(cr3) ever seen for it (shuffle detection)
    std::unordered_map<DWORD, std::unordered_set<std::uint64_t>> pidHistory;
    // pid -> {last_shown, suppressed_count} (coalescing)
    struct CoalesceState {
        std::chrono::steady_clock::time_point last;
        int suppressed = 0;
    };
    std::unordered_map<DWORD, CoalesceState> coalesce;
    std::unordered_set<std::uint64_t> seenCr3; // --new-only

    std::optional<std::pair<std::uint64_t, std::chrono::system_clock::time_point>> clockAnchor;

    auto finish = []() -> int {
        disarmAndClose();
        std::cout << col(kDim, "\n[cr3logger] disarmed, exiting.") << "\n";
        return 0;
    };

    // --show-unresolved correlation state: when did each vCPU last confirm
    // running the target, and what unresolved "shadow" CR3 (if any) did we
    // last see on that vCPU - so a change to a *different* unresolved value
    // can be flagged the same way a real shuffle would be.
    const auto shadowCorrelationWindow = std::chrono::milliseconds(opts.shadowWindowMs);
    std::unordered_map<std::uint32_t, std::chrono::steady_clock::time_point> vcpuTargetSeen;
    std::unordered_map<std::uint32_t, std::uint64_t> vcpuLastShadow;

    long shown = 0;
    std::vector<KvmCr3Event> buf(64);

    while (!g_stop) {
        ssize_t n = read(fd, buf.data(), buf.size() * sizeof(KvmCr3Event));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            std::cerr << col(kRed, std::string("[cr3logger] read error: ") + std::strerror(errno))
                      << "\n";
            break;
        }

        if (n == 0) {
            continue;
        }

        resolver.tick();

        size_t count = static_cast<size_t>(n) / sizeof(KvmCr3Event);
        for (size_t i = 0; i < count && !g_stop; ++i) {
            const KvmCr3Event& ev = buf[i];

            if (!clockAnchor) {
                clockAnchor = {ev.ns, std::chrono::system_clock::now()};
            }

            auto eventTime = [&](std::uint64_t ns) {
                auto delta = std::chrono::nanoseconds(
                    static_cast<std::int64_t>(ns) - static_cast<std::int64_t>(clockAnchor->first));
                auto tp = clockAnchor->second
                    + std::chrono::duration_cast<std::chrono::system_clock::duration>(delta);

                std::time_t tt = std::chrono::system_clock::to_time_t(tp);
                auto ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch())
                    % 1000;

                std::tm tmv{};
                localtime_r(&tt, &tmv);

                char buf2[16];
                std::snprintf(buf2,
                              sizeof(buf2),
                              "%02d:%02d:%02d.%03d",
                              tmv.tm_hour,
                              tmv.tm_min,
                              tmv.tm_sec,
                              static_cast<int>(ms.count()));

                return std::string(buf2);
            };

            // Resolve new_cr3 unconditionally - needed for display, shuffle
            // tracking, and (non-target mode) the filter check itself.
            auto newProc = resolver.resolve(phys(ev.new_cr3));

            bool entering = wantTarget && newProc && filter.matches(*newProc);
            if (entering) {
                vcpuTargetSeen[ev.vcpu_id] = std::chrono::steady_clock::now();
            }

            std::optional<ProcInfo> oldProc;
            bool leaving = false;
            if (wantTarget && !entering) {
                // Only bother resolving old_cr3 (a second lookup) when we
                // actually need it to decide whether this is the target's
                // "yielded back to whatever" half.
                oldProc = resolver.resolve(phys(ev.old_cr3));
                leaving = oldProc && filter.matches(*oldProc);
            }

            if (wantTarget && !entering && !leaving) {
                // Doesn't resolve to the target on either side. Still worth a
                // look if it's completely unresolvable (no known process at
                // all - see file header) AND happened on a vCPU that just ran
                // the target: that's the fingerprint of a second, separate
                // page table used briefly by the same thread and never linked
                // into the normal process list, so ordinary resolution has no
                // way to ever find it.
                if (opts.showUnresolved && !newProc) {
                    auto it = vcpuTargetSeen.find(ev.vcpu_id);
                    bool recentTargetOnThisVcpu = it != vcpuTargetSeen.end()
                        && (std::chrono::steady_clock::now() - it->second)
                            < shadowCorrelationWindow;

                    if (recentTargetOnThisVcpu) {
                        std::uint64_t key = phys(ev.new_cr3);
                        std::uint64_t& lastShadow = vcpuLastShadow[ev.vcpu_id];
                        bool isNewShadow = (lastShadow == 0 || lastShadow != key);

                        std::cout << col(kDim, eventTime(ev.ns)) << " "
                                  << col(kMagenta, isNewShadow ? "[SHADOW-NEW]" : "[SHADOW]")
                                  << " vcpu" << ev.vcpu_id << " unresolved cr3 " << fmtCr3(key)
                                  << " (this vcpu ran the target within the last "
                                  << opts.shadowWindowMs << "ms; old=" << fmtCr3(ev.old_cr3)
                                  << ")\n";

                        lastShadow = key;
                    }
                }

                continue; // doesn't involve the target at all
            }

            DWORD pid = 0;
            std::string name;
            bool haveIdentity = false;

            if (wantTarget) {
                const ProcInfo& p = entering ? *newProc : *oldProc;
                pid = p.pid;
                name = p.name;
                haveIdentity = true;

                if (pid != announcedPid) {
                    std::cerr << col(kGreen,
                                     "[cr3logger] tracking PID " + std::to_string(pid) + " (" + name
                                         + ")")
                              << "\n";
                    announcedPid = pid;
                }
            } else if (newProc) {
                pid = newProc->pid;
                name = newProc->name;
                haveIdentity = true;
            } else {
                // Real resolution genuinely failed even after a forced
                // refresh - drop it silently rather than fabricate a
                // placeholder. See the file header for why this happens.
                continue;
            }

            // --- Shuffle detection: always shown, bypasses every other filter ---
            // Only meaningful on the "entering" half - `leaving` means new_cr3
            // is whatever the target yielded to (System, generally), which
            // isn't a CR3 belonging to `pid` at all.
            bool checkShuffle = haveIdentity && pid != 4 && (!wantTarget || entering);
            if (checkShuffle) {
                std::uint64_t key = phys(ev.new_cr3);
                auto& known = pidHistory[pid];

                if (!known.empty() && !known.count(key)) {
                    std::uint64_t prev = *known.begin();

                    std::cout << col(kDim, eventTime(ev.ns)) << " " << col(kRed, "[CR3-SHUFFLE]")
                              << " PID " << pid << " (" << name << "): " << fmtCr3(prev) << " -> "
                              << fmtCr3(key) << " (vcpu" << ev.vcpu_id << ", " << (known.size() + 1)
                              << " CR3s seen total for this PID)\n";

                    known.insert(key);
                    if (opts.count && ++shown >= opts.count) {
                        return finish();
                    }

                    continue;
                }

                known.insert(key);
            }

            if (opts.newOnly) {
                std::uint64_t key = phys(ev.new_cr3);
                if (seenCr3.count(key)) {
                    continue;
                }

                seenCr3.insert(key);
            }

            if (wantTarget) {
                if (!opts.showIdleReturn && !entering) {
                    continue;
                }
            } else {
                if (!opts.showIdleReturn && pid == 4) {
                    continue;
                }
            }

            int repeats = 0;
            if (opts.coalesceMs && !opts.newOnly) {
                auto now = std::chrono::steady_clock::now();
                auto& state = coalesce[pid];
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - state.last).count()
                    < opts.coalesceMs) {
                    ++state.suppressed;
                    continue;
                }

                repeats = state.suppressed;
                state.last = now;
                state.suppressed = 0;
            }

            std::string nameDisp = name.substr(0, 16);
            std::string pidDisp = std::to_string(pid);
            std::string repeatsDisp = repeats
                ? " " + col(kDim, "(+" + std::to_string(repeats) + ")")
                : "";

            std::cout << col(kDim, eventTime(ev.ns)) << " "
                      << col(kYellow, padRight("vcpu" + std::to_string(ev.vcpu_id), 6)) << " "
                      << col(kMagenta, padRight(pidDisp, 8)) << " "
                      << col(kMagenta, padRight(nameDisp, 16)) << " "
                      << col(kCyan, fmtCr3(ev.old_cr3)) << " -> " << col(kCyan, fmtCr3(ev.new_cr3))
                      << repeatsDisp << "\n";

            if (opts.count && ++shown >= opts.count) {
                return finish();
            }
        }
    }

    return finish();
}
