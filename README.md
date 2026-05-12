# memtrace-runtime

> A Windows runtime memory analyser -> injects a payload DLL into any live or freshly launched process, hooks its heap functions via IAT patching, and streams allocation events to a live dashboard with leak detection, call site ranking, and also but not limited to JSON export.

---

## How it works

```
memtrace-runtime.exe                   target process (any .exe)
──────────────────────                 ──────────────────────────────────
1. OpenProcess / CreateProcess         (running or freshly suspended)
2. VirtualAllocEx + WriteProcessMemory  write DLL path into target memory
3. CreateRemoteThread(LoadLibraryA)     inject payload-dll.dll
                                       4. DllMain fires
                                       5. Hooks HeapAlloc/HeapFree/
                                          HeapReAlloc/malloc/free/
                                          realloc/calloc via IAT patching
                                          across ALL loaded modules
                                       6. Writes AllocEvents to a named
                                          shared memory ring buffer
7. Reads ring buffer continuously      <- events stream in real-time
8. Live dashboard refreshes every <N> ms
9. On Ctrl+C or process exit:
   - prints final leak report
   - optionally writes JSON report
```

### IAT patching and why its safe

Instead of overwriting function *code* (JMP trampolines), we overwrite the **Import Address Table**, the data table of function pointers that the linker fills at load time, this means:

- no code pages are modified -> works under DEP and CFG
- fully reversible (write the original pointer back)
- no risk of patching in the middle of an instruction
- works on all x64 Windows versions

---

## Building

### Requirements

- Visual Studio
- Windows SDK 10.0
- **Run VS as Administrator** (process injection requires `PROCESS_ALL_ACCESS`)

### Steps

```
1. Open memtrace-runtime.sln in Visual Studio
2. Select Configuration: Release | x64
3. Build -> Build Solution  (Ctrl+Shift+B)

Output in:  bin\Release\x64\
  memtrace-runtime.exe   <- the analyser host
  payload-dll.dll        <- the injected hook payload
```

> Both files **must be in the same directory**. The host auto detects the DLL path at its own executable location

---

## Usage

```
memtrace-runtime.exe --pid <PID> | --launch <exe.exe> [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--pid <N>` | — | Attach to an already-running process by PID |
| `--launch <exe>` | — | Launch and instrument a new process |
| `--args "<args>"` | — | Arguments passed to the launched process |
| `--report-interval <ms>` | 1000 | Live dashboard refresh rate in milliseconds |
| `--top-allocs <N>` | 10 | Show top N allocation sites by total bytes |
| `--output <file.json>` | — | Write final report to a JSON file on exit |
| `--stack` | off | Resolve stack frame symbols (requires `.pdb` files) |
| `--dump-stacks` | off | dump full stack traces for large allocations |
| `--threshold <bytes>` | 0 | Ignore allocations smaller than N bytes |
| `--duration <s>` | 0 | Auto-stop after N seconds (0 = run until exit) |
| `--no-color` | off | Disable ANSI colour output |
| `--quiet` | off | Skip live dashboard, print only the final report |

### Examples

```bat
REM Attach to a running process
memtrace-runtime.exe --pid 1234

REM Launch and instrument notepad with symbol resolution
memtrace-runtime.exe --launch notepad.exe --stack --output notepad_leaks.json

REM Profile a server for 60 seconds, ignore small allocs, save JSON
memtrace-runtime.exe --pid 5678 --threshold 1024 --duration 60 --output server.json

REM Run quietly, only print the final summary
memtrace-runtime.exe --launch myapp.exe --args "--config release.cfg" --quiet

REM Attach, show top 20 sites, refresh every 500ms
memtrace-runtime.exe --pid 9999 --top-allocs 20 --report-interval 500
```

---

## Live Dashboard

```
 memtrace-runtime | target PID 4724   | elapsed 6.0s
================================================================================

  live allocations:  4              current heap:  256 B
  peak heap:         2.57 KiB       total allocs:  24
  total freed:       20             dropped events: 0

  top 10 allocation sites by total bytes (growth since last sample):
  count     total         growth      call-site
  --------  ------------  ----------  ------------------------------------------------
  20        3.45 KiB      stable      RtlUserThreadStart+0x2c
  1         64 B          stable      0x00007ff7dc1e851f
            [1] 0x00007ff7dc1e4e1e
            [2] 0x00007ff7dc1f2574
            [3] 0x00007ff7dc1feb56
  1         64 B          stable      0x00007ff7dc1f2671
            [1] 0x00007ff7dc1feb56
            [2] 0x00007ff7dc1f3667
            [3] 0x00007ff7dc1f0280
  1         64 B          stable      0x00007ff7dc1fec9e
            [1] 0x00007ff7dc1febb2
            [2] 0x00007ff7dc1f3667
            [3] 0x00007ff7dc1f0280
  1         64 B          stable      0x00007ff7dc1e8631
            [1] 0x00007ff7dc1fed47
            [2] 0x00007ff7dc1febb2
            [3] 0x00007ff7dc1f3667

  live allocations -> 4 allocations, 256 B
  [i] live allocations stable (no growth detected). likely caches/pools
  [next analysis in 5 seconds]

  [press Ctrl+C to stop and print final report]
```

---

## Final Report

Printed on exit (Ctrl+C, process termination, or `--duration` timeout):

```
================== memtrace FINAL REPORT ==================
  target PID          : 4724
  total allocations   : 24
  total frees         : 20
  total alloc bytes   : 3.70 KiB
  peak live bytes     : 2.57 KiB
  live at exit        : 4 allocs, 256 B
  dropped events      : 0

  Stable allocations (likely caches/pools):
    ├─ 5 stable allocation sites
    └─ Total stable memory: 3.70 KiB

  VERDICT: CLEAN - No memory leaks detected
```

---

## JSON Output (`--output <name>.json`)

```json
{
  "target_pid": 10920,
  "summary": {
    "total_alloc_count": 24,
    "total_free_count":  20,
    "total_alloc_bytes": 3788,
    "peak_bytes":        2636,
    "live_alloc_count":  4,
    "live_alloc_bytes":  256,
    "dropped_events":    0
  },
  "live_allocations": [
    {"ptr": 1769338272288, "size": 64},
    {"ptr": 1769338100656, "size": 64},
    {"ptr": 1769338272048, "size": 64},
    {"ptr": 1769338100816, "size": 64}
  ],
  "top_sites": [
    {"count": 20, "total_bytes": 3532, "stack": ["0x7ffe9c5e5a6c"]},
    {"count": 1, "total_bytes": 64, "stack": ["0x7ff7dc1e851f", "0x7ff7dc1e4e1e", "0x7ff7dc1f2574", "0x7ff7dc1feb56", "0x7ff7dc1f3667", "0x7ff7dc1f0280", "0x7ff7dc1e1935", "0x7ffe9c47dbe7"]},
    {"count": 1, "total_bytes": 64, "stack": ["0x7ff7dc1f2671", "0x7ff7dc1feb56", "0x7ff7dc1f3667", "0x7ff7dc1f0280", "0x7ff7dc1e1935", "0x7ffe9c47dbe7", "0x7ffe9c5e5a6c"]},
    {"count": 1, "total_bytes": 64, "stack": ["0x7ff7dc1fec9e", "0x7ff7dc1febb2", "0x7ff7dc1f3667", "0x7ff7dc1f0280", "0x7ff7dc1e1935", "0x7ffe9c47dbe7", "0x7ffe9c5e5a6c"]},
    {"count": 1, "total_bytes": 64, "stack": ["0x7ff7dc1e8631", "0x7ff7dc1fed47", "0x7ff7dc1febb2", "0x7ff7dc1f3667", "0x7ff7dc1f0280", "0x7ff7dc1e1935", "0x7ffe9c47dbe7", "0x7ffe9c5e5a6c"]}
  ]
}

```

---

## Symbol Resolution (`--stack`)

When `--stack` is passed, the host calls `DbgHelp!SymFromAddr` on each captured stack frame but For this to work you need to make sure that you:

1. Build your target with **`/Zi`** (generate `.pdb` files)
2. Place the `.pdb` files alongside the `.exe`, or set `_NT_SYMBOL_PATH`:

Without symbols, raw hex addresses are shown (`0x00007ff812340abc`).

---

## Hooked Functions

| Function | Module |
|----------|--------|
| `HeapAlloc` | `kernel32.dll` |
| `HeapFree` | `kernel32.dll` |
| `HeapReAlloc` | `kernel32.dll` |
| `VirtualAlloc` | `kernel32.dll` |
| `VirtualFree` | `kernel32.dll` |
| `malloc` | `ucrtbase.dll` / `msvcrt.dll` |
| `free` | `ucrtbase.dll` / `msvcrt.dll` |
| `realloc` | `ucrtbase.dll` / `msvcrt.dll` |
| `calloc` | `ucrtbase.dll` / `msvcrt.dll` |

All functions are hooked across **every module** loaded in the target process at injection time (via `EnumProcessModules` + per module IAT patching)

---

## Shared Memory IPC Protocol

The payload DLL and host communicate via a named shared memory object:

```
Name:   "Local\memtrace_<pid>"
Layout: [ SharedHeader ][ AllocEvent[65536] ]  (ring buffer)
```

The ring buffer is a **lock-free SPSC queue** (single producer = target, single consumer = host). Events are never locked and the payload writes with `InterlockedIncrement` sequence numbers; the host reads by checking `event.sequence == read_seq`.

---

## Permissions

Attaching to another process requires **SeDebugPrivilege**, which typically means running as Administrator:

```
Right-click memtrace-runtime.exe -> Run as administrator
```

Or from an elevated command prompt.

---

## Limitations

- x64 targets only (matching architecture required for DLL injection)
- 32-bit processes are not supported
- Anti-cheat or anti-tamper protected processes will reject injection
- The injected DLL uses a **static CRT** to avoid circular dependency when hooking `ucrtbase.dll`
- Stack capture uses `RtlCaptureStackBackTrace` (8 frames max by default)

---

## File Structure

```
memtrace-runtime/
├── memtrace-runtime.sln
├── shared/
│   └── ipc_protocol.hpp          <- shared memory layout, ring buffer protocol
├── memtrace-runtime/
│   ├── memtrace-runtime.vcxproj
│   └── src/
│       └── main.cpp              <- CLI, injector, event pump, dashboard, reports
└── payload-dll/
    ├── payload-dll.vcxproj
    ├── include/
    │   └── iat_hook.hpp          <- IAT patching engine
    └── src/
        └── dllmain.cpp           <- DllMain, hook detours, shared memory writer
```

---

## License

MIT © 2026
