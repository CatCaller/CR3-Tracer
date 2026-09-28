#!/usr/bin/env python3.13
"""cr3logger.py - CR3-switch logger with process name resolution for baykus.

Requires the 0002-cr3-tracer kernel patch built into kvm-amd.ko and loaded.
Resolves CR3 values to process names/PIDs using vmmpyc memory introspection.

IMPORTANT: vmmpyc (../KVM-Folders/MemProcFS/files/vmmpyc.so) is built against Python 3.13 specifically -
it segfaults under 3.14 (MemProcFS's embedded Python-plugin subsystem is
incompatible with newer CPython internals) unless '-disable-python' is passed
to Vmm(), which this script already does. Run this with python3.13, not
whatever 'python3' defaults to on this host.

Usage:
    sudo python3.13 cr3logger.py                        # log everything, resolved
    sudo python3.13 cr3logger.py --pid 4128              # only this PID's switches
    sudo python3.13 cr3logger.py --name notepad          # only matching process(es)
                                                          #   (waits if not started yet)
    sudo python3.13 cr3logger.py --no-pid-resolve        # raw CR3 only, no vmmpyc
    sudo python3.13 cr3logger.py -n 50                   # stop after 50 events
"""
import argparse
import fcntl
import os
import signal
import struct
import sys
import time

DEVICE = "/dev/kvm_cr3trace"

# Must match struct kvm_cr3_event in arch/x86/kvm/svm/cr3_trace.h exactly:
#   __u64 ns; __u32 vcpu_id; __u32 pad; __u64 old_cr3; __u64 new_cr3;
EVENT_FMT = "<QIIQQ"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
assert EVENT_SIZE == 32

# Linux ioctl encoding: for a no-arg ioctl, _IO(type, nr) = (type << 8) | nr
def _IO(type_, nr):
    return (type_ << 8) | nr

CR3TRACE_IOC_ARM = _IO(0xC3, 1)      # 0x0000c301
CR3TRACE_IOC_DISARM = _IO(0xC3, 2)   # 0x0000c302
CR3TRACE_IOC_FLUSH = _IO(0xC3, 3)    # 0x0000c303

# CR3 low bits (0-11) can carry a PCID when PCID is enabled; bit 63 is the
# "no-TLB-flush" hint on a MOV-to-CR3. Neither is part of the physical page
# table root address, so mask both off before comparing against a DTB.
CR3_PHYS_MASK = 0x0000_FFFF_FFFF_F000

TARGET_REFRESH_INTERVAL = 2.0  # seconds between re-resolving --pid/--name target
PROCLIST_REFRESH_INTERVAL = 2.0  # seconds between forced MemProcFS process-list refreshes
UNRESOLVED_MAX_RETRIES = 3  # give up relabeling a CR3 as "unknown" -> "hidden/driver?" after this many refreshes
OPT_REFRESH_ALL = 0x2001ffff00000000

RESET = "\033[0m"
DIM = "\033[2m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
MAGENTA = "\033[35m"


def fmt_cr3(v):
    return f"0x{v:016x}"


def phys(cr3_value):
    return cr3_value & CR3_PHYS_MASK


def event_time_str(ns, anchor):
    """Format an event's actual kernel timestamp (ktime_get_ns(), monotonic)
    as a wall-clock HH:MM:SS.mmm string, using `anchor` = (first_ns, first_wall)
    to project it - NOT time.time() at print time, which drifts arbitrarily far
    from reality if the reader ever falls behind a burst of real events.
    """
    anchor_ns, anchor_wall = anchor
    wall = anchor_wall + (ns - anchor_ns) / 1e9
    lt = time.localtime(wall)
    ms = int(wall * 1000) % 1000
    return f"{time.strftime('%H:%M:%S', lt)}.{ms:03d}"


def find_qemu_pid(vm_name):
    """Find the real qemu-system-x86_64 PID for vm_name, by inspecting /proc
    directly. pgrep -f is unreliable here: it matches on the full cmdline of
    *any* process, including unrelated ones (e.g. swtpm's socket path contains
    both 'qemu' and the VM name) and even this script's own shell wrapper.
    """
    needle = f"guest={vm_name}".encode()
    try:
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return None

    for pid in pids:
        try:
            with open(f"/proc/{pid}/comm", "rb") as f:
                comm = f.read().strip()
        except OSError:
            continue

        if not comm.startswith(b"qemu-system"):
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read()
        except OSError:
            continue

        if needle in cmdline:
            return pid

    return None


def setup_vmm(qemu_pid, qmp_socket):
    """Initialize vmmpyc and connect to the QEMU instance."""
    try:
        sys.path.insert(
            0,
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                '..',
                'KVM-Folders',
                'MemProcFS',
                'files',
            ),
        )
        from vmmpyc import Vmm
    except ImportError as e:
        print(f"error: failed to import vmmpyc: {e}", file=sys.stderr)
        return None

    try:
        device_str = f'qemu://hugepage-pid={qemu_pid},qmp={qmp_socket}'
        # -disable-python: MemProcFS's embedded forensic-Python-plugin loader
        # segfaults on this host's CPython. We don't use that subsystem, so
        # skipping its init entirely sidesteps the crash.
        vmm = Vmm(['-disable-python', '-device', device_str])
        return vmm
    except Exception as e:
        print(f"error: failed to connect to QEMU instance: {e}", file=sys.stderr)
        return None


class Target:
    """Tracks the DTB set of a --pid/--name filter target, re-resolving
    periodically so a process that restarts (or hasn't started yet) is
    picked back up automatically.
    """

    def __init__(self, vmm, pid=None, name=None):
        self.vmm = vmm
        self.pid = pid
        self.name = name.lower() if name else None
        self.dtbs = frozenset()
        self.resolved_pid = None
        self.resolved_name = None
        self._last_refresh = 0.0
        self._was_found = False

    def active(self):
        return self.pid is not None or self.name is not None

    def refresh(self, force=False):
        now = time.monotonic()
        if not force and (now - self._last_refresh) < TARGET_REFRESH_INTERVAL:
            return

        self._last_refresh = now

        proc = None
        try:
            if self.pid is not None:
                proc = self.vmm.process(self.pid)
            else:
                for p in self.vmm.process_list():
                    if self.name in p.name.lower():
                        proc = p
                        break
        except Exception:
            proc = None

        if proc is None:
            if self._was_found:
                who = self.resolved_name or self.name or self.pid
                print(
                    c(YELLOW, f"[cr3logger] target '{who}' no longer running, waiting..."),
                    file=sys.stderr,
                )

            self.dtbs = frozenset()
            self.resolved_pid = None
            self.resolved_name = None
            self._was_found = False
            return

        dtbs = {phys(proc.dtb)}
        if getattr(proc, 'dtb_user', 0):
            dtbs.add(phys(proc.dtb_user))

        if dtbs != self.dtbs:
            print(
                c(GREEN, f"[cr3logger] tracking PID {proc.pid} ({proc.name}), dtb={fmt_cr3(proc.dtb)}"),
                file=sys.stderr,
            )

        self.dtbs = frozenset(dtbs)
        self.resolved_pid = proc.pid
        self.resolved_name = proc.name
        self._was_found = True

    def matches(self, old_cr3, new_cr3):
        if not self.dtbs:
            return False

        return phys(old_cr3) in self.dtbs or phys(new_cr3) in self.dtbs


color_enabled = True


def c(code, s):
    return f"{code}{s}{RESET}" if color_enabled else s


def main():
    global color_enabled
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument("--device", default=DEVICE)
    ap.add_argument("--vm-name", default="baykus", help="libvirt/QEMU guest name (default: baykus)")
    ap.add_argument(
        "--qemu-pid",
        type=int,
        help="QEMU PID for memory introspection (auto-detect if not provided)",
    )
    ap.add_argument("--qmp-socket", default="/tmp/qmp-baykus.sock", help="QMP socket path for QEMU")
    ap.add_argument(
        "--no-pid-resolve",
        action="store_true",
        help="disable PID/name resolution, show only raw CR3 values",
    )
    ap.add_argument(
        "--pid",
        type=int,
        help="only show CR3 switches involving this PID (must already be running)",
    )
    ap.add_argument(
        "--name",
        help="only show CR3 switches involving processes whose name contains this "
             "(case-insensitive); if not running yet, waits for it to start",
    )
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument(
        "--show-idle-return",
        action="store_true",
        help="also print the immediate bounce back to the System/idle process after each "
             "switch (suppressed by default - it carries no information the next line doesn't "
             "already imply, and is most of the visual noise on a busy guest)",
    )
    ap.add_argument(
        "--coalesce-ms",
        type=int,
        default=250,
        help="collapse repeat entries of the *same* PID within this many milliseconds into one "
             "line with a '(+N)' repeat count, instead of printing each one (default: 250, 0 disables). "
             "A busy background process (Steam, telemetry services, etc.) gets rescheduled across "
             "vCPUs dozens of times a second even when idle-return lines are hidden - this is what "
             "actually controls how spammy the default view feels. Ignored when --new-only is set.",
    )
    ap.add_argument(
        "--new-only",
        action="store_true",
        help="show each distinct CR3 (page table root) only the first time it's ever seen, then "
             "never again - i.e. new processes/threads showing up, not the routine scheduling "
             "churn of ones you've already seen. This is usually what you actually want instead "
             "of tuning --coalesce-ms: a chatty background process (Steam, telemetry services) "
             "reuses the same CR3 every time, so it prints once and goes silent.",
    )
    ap.add_argument(
        "-n", "--count",
        type=int,
        default=0,
        help="stop after N *matching* events (default: run forever)",
    )
    args = ap.parse_args()

    color_enabled = not args.no_color

    if args.pid and args.name:
        print("error: --pid and --name are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    want_resolve = not args.no_pid_resolve or args.pid or args.name
    if args.no_pid_resolve and (args.pid or args.name):
        print(
            "error: --no-pid-resolve conflicts with --pid/--name (targeting requires resolution)",
            file=sys.stderr,
        )
        sys.exit(1)

    qemu_pid = args.qemu_pid
    if not qemu_pid and want_resolve:
        qemu_pid = find_qemu_pid(args.vm_name)
        if not qemu_pid:
            print(
                c(YELLOW, f"[cr3logger] no running qemu-system process found for guest '{args.vm_name}'"),
                file=sys.stderr,
            )

    vmm = None
    if want_resolve and qemu_pid:
        print(c(DIM, f"[cr3logger] connecting to QEMU (PID {qemu_pid})..."), file=sys.stderr)
        vmm = setup_vmm(qemu_pid, args.qmp_socket)
        if vmm:
            print(c(GREEN, "[cr3logger] vmmpyc initialized"), file=sys.stderr)
        elif args.pid or args.name:
            print(
                c(RED, "[cr3logger] cannot target --pid/--name without vmmpyc; aborting"),
                file=sys.stderr,
            )
            sys.exit(1)

    target = (
        Target(vmm, pid=args.pid, name=args.name)
        if vmm and (args.pid or args.name)
        else None
    )

    if target:
        target.refresh(force=True)
        if not target._was_found:
            who = args.name or args.pid
            print(
                c(YELLOW, f"[cr3logger] waiting for process matching '{who}' to start..."),
                file=sys.stderr,
            )

    try:
        fd = os.open(args.device, os.O_RDONLY)
    except PermissionError:
        print(f"error: no permission to open {args.device} (try sudo)", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(
            f"error: {args.device} not found - is the cr3-tracer kvm_amd.ko loaded?",
            file=sys.stderr,
        )
        sys.exit(1)

    def disarm_and_exit(*_):
        try:
            fcntl.ioctl(fd, CR3TRACE_IOC_DISARM)
        except OSError:
            pass

        os.close(fd)
        print(c(DIM, "\n[cr3logger] disarmed, exiting."))
        sys.exit(0)

    signal.signal(signal.SIGINT, disarm_and_exit)
    signal.signal(signal.SIGTERM, disarm_and_exit)

    fcntl.ioctl(fd, CR3TRACE_IOC_FLUSH)
    fcntl.ioctl(fd, CR3TRACE_IOC_ARM)
    print(c(GREEN, f"[cr3logger] armed, reading from {args.device} (Ctrl+C to stop)"))

    if target or vmm:
        header = f"{'TIME':<12} {'VCPU':<6} {'PID':<8} {'PROCESS':<20} {'OLD CR3':<18} {'NEW CR3':<18}"
    else:
        header = f"{'TIME':<12} {'VCPU':<6} {'OLD CR3':<18} {'NEW CR3':<18}"

    print(c(DIM, header))

    n = 0
    buf_events = 64
    # phys(cr3) -> [pid_or_None, name_or_None, retries]. A miss (pid is None) gets
    # retried across periodic refreshes; after UNRESOLVED_MAX_RETRIES it's treated
    # as a real, persistently-hidden page table (VBS/Secure Kernel, a driver's own
    # address space, etc.) rather than just "MemProcFS hasn't caught up yet".
    resolve_cache = {}
    coalesce = {}  # pid -> [last_shown_monotonic, suppressed_count]
    seen_cr3 = set()  # phys(cr3) values already shown, only used with --new-only
    pid_cr3_history = {}  # pid -> set of phys(cr3) ever seen for it, for shuffle detection
    last_proclist_refresh = 0.0
    # Wall-clock/kernel-clock correlation, established from the first real event, so
    # displayed timestamps reflect when the switch actually happened in the kernel
    # (ktime_get_ns(), monotonic) rather than whenever this script got around to
    # printing it - those can differ by a lot if a burst outpaces processing.
    clock_anchor = None  # (first_event_ns, wall_time_at_that_ns)

    while True:
        try:
            chunk = os.read(fd, EVENT_SIZE * buf_events)
        except OSError as e:
            print(c(RED, f"[cr3logger] read error: {e}"), file=sys.stderr)
            break
        if not chunk:
            continue

        if target:
            target.refresh()

        if vmm and (time.monotonic() - last_proclist_refresh) > PROCLIST_REFRESH_INTERVAL:
            last_proclist_refresh = time.monotonic()
            pending = [k for k, e in resolve_cache.items() if e[0] is None and e[2] < UNRESOLVED_MAX_RETRIES]
            if pending:
                try:
                    vmm.set_config(OPT_REFRESH_ALL, 1)
                    procs = vmm.process_list()
                    by_dtb = {}
                    for p in procs:
                        by_dtb[phys(p.dtb)] = p
                        if getattr(p, 'dtb_user', 0):
                            by_dtb[phys(p.dtb_user)] = p
                    for key in pending:
                        proc = by_dtb.get(key)
                        if proc:
                            resolve_cache[key][0] = proc.pid
                            resolve_cache[key][1] = proc.name
                        else:
                            resolve_cache[key][2] += 1
                except Exception:
                    pass

        for off in range(0, len(chunk) - EVENT_SIZE + 1, EVENT_SIZE):
            ns, vcpu_id, _pad, old_cr3, new_cr3 = struct.unpack_from(EVENT_FMT, chunk, off)

            if clock_anchor is None:
                clock_anchor = (ns, time.time())

            if target and not target.matches(old_cr3, new_cr3):
                continue

            # Resolve pid/name first - shuffle detection and --new-only both need it
            # to be settled before any suppression logic runs.
            if target:
                pid, name = target.resolved_pid, target.resolved_name
                unresolvable = False
            elif vmm:
                key = phys(new_cr3)
                if key not in resolve_cache:
                    try:
                        proc = None
                        for p in vmm.process_list():
                            if phys(p.dtb) == key or (getattr(p, 'dtb_user', 0) and phys(p.dtb_user) == key):
                                proc = p
                                break
                        resolve_cache[key] = [proc.pid, proc.name, 0] if proc else [None, None, 0]
                    except Exception:
                        resolve_cache[key] = [None, None, 0]
                pid, name = resolve_cache[key][0], resolve_cache[key][1]
                unresolvable = pid is None and resolve_cache[key][2] >= UNRESOLVED_MAX_RETRIES
            else:
                pid, name = None, None
                unresolvable = False

            # Shuffle detection: an *already-known* PID showing up with a CR3 we've
            # never seen for it before. A stable process has exactly one CR3 for its
            # whole life; a new one appearing later means something (typically a
            # kernel-mode driver - anti-cheat/DRM is the classic case) rebuilt its
            # page tables out from under it. Always shown, regardless of --new-only/
            # --coalesce-ms/--show-idle-return, since it's rare and specifically
            # the signal those flags would otherwise bury.
            # In target mode, pid/name are always the target's own identity (used
            # for display in both directions), but new_cr3 only actually belongs to
            # the target when entering - on the leaving half it's whatever the
            # target yielded to (System, generally). Restrict to entering there so
            # "left the target" doesn't get misattributed as "target's PID shuffled".
            check_shuffle = pid is not None and pid != 4 and (not target or phys(new_cr3) in target.dtbs)
            if check_shuffle:
                key = phys(new_cr3)
                known = pid_cr3_history.get(pid)
                if known is not None and key not in known:
                    prev_cr3 = next(iter(known))
                    print(
                        f"{c(DIM, event_time_str(ns, clock_anchor))} "
                        f"{c(RED, '[CR3-SHUFFLE]')} "
                        f"PID {pid} ({name}): {fmt_cr3(prev_cr3)} -> {fmt_cr3(key)} "
                        f"(vcpu{vcpu_id}, {len(known)+1} CR3s seen total for this PID)"
                    )
                    known.add(key)
                    n += 1
                    if args.count and n >= args.count:
                        disarm_and_exit()
                    continue
                elif known is None:
                    pid_cr3_history[pid] = {key}

            if args.new_only:
                key = phys(new_cr3)
                if key in seen_cr3:
                    continue
                seen_cr3.add(key)

            if target:
                if not args.show_idle_return:
                    entering = phys(new_cr3) in target.dtbs
                    if not entering:
                        continue  # leaving target -> back to whatever; implied by the next entry line
            elif vmm:
                if not args.show_idle_return and pid == 4:
                    continue  # bounced straight back to System/idle - no new information

            repeats = 0
            if args.coalesce_ms and not args.new_only and pid is not None:
                now_mono = time.monotonic()
                last_ts, suppressed = coalesce.get(pid, (0.0, 0))
                if (now_mono - last_ts) * 1000 < args.coalesce_ms:
                    coalesce[pid] = (last_ts, suppressed + 1)
                    continue
                repeats = suppressed
                coalesce[pid] = (now_mono, 0)

            ts_label = event_time_str(ns, clock_anchor)
            vcpu_label = f"vcpu{vcpu_id}"

            if vmm:
                label = "hidden/driver?" if unresolvable else "unknown"
                name_disp = (name or label)[:16].ljust(16)
                pid_disp = (str(pid) if pid else "?????").ljust(8)
                repeats_disp = c(DIM, f" (+{repeats})") if repeats else ""
                print(
                    f"{c(DIM, ts_label)} "
                    f"{c(YELLOW, vcpu_label.ljust(6))} "
                    f"{c(MAGENTA, pid_disp)} "
                    f"{c(MAGENTA, name_disp)} "
                    f"{c(CYAN, fmt_cr3(old_cr3))} -> {c(CYAN, fmt_cr3(new_cr3))}"
                    f"{repeats_disp}"
                )
            else:
                print(
                    f"{c(DIM, ts_label)} "
                    f"{c(YELLOW, vcpu_label.ljust(6))} "
                    f"{c(CYAN, fmt_cr3(old_cr3))} -> {c(CYAN, fmt_cr3(new_cr3))}"
                )
            n += 1
            if args.count and n >= args.count:
                disarm_and_exit()


if __name__ == "__main__":
    main()
