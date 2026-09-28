# CR3-Tracer

Logs CR3 changes from a Windows guest on patched AMD KVM. The C++ logger uses `/dev/kvm_cr3trace` and MemProcFS. Build the running kernel's `kvm-amd` module with `0002-cr3-tracer.patch` first. Keep `KVM-Folders` beside this folder.

```sh
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp/build
sudo ./cpp/build/cr3logger --new-only
```

Use `--name notepad` or `--pid 1234` to filter. `cr3logger.py` is the Python version.
