 The program was translated with the help of AI; the overall structure may look like it was generated.
Features
- Metrics: CPU%, RSS/ΔRSS, disk I/O, fds, nice/priority, threads, cmdline — all from procfs.
- Anomaly detection: hung (CPU-bound, no I/O), memleak (linear RSS growth via regression), fdleak, zombie, iostorm.
- TUI: process tree (like Task Manager), sortable table, charts, action log, mouse support, Russian-layout hotkeys.
- Process groups: kill whole categories (browsers, messengers, telemetry, games, builds) with three-layer protection against self-harm.
- Local AI (Ollama): explains a selected process on keypress; model unloads right after (keep_alive=0).
- Security tab: heuristic malware/autostart/network checks, optional hash lookup via DeepSeek (opt-in, capped, hash-only).
- System tab: power/services/network/packages control via pkexec, one password per session.
- Smart Kill: SIGTERM → SIGABRT(+core) → SIGKILL, with PID-reuse protection, single-process or whole-tree scope, and supervisor-restart detection.
## Build & Install

Requires Linux with procfs, Go 1.24+ and an ANSI-capable terminal.

```bash
git clone https://github.com/sw1ke/deadeye && cd deadeye
make                    # builds bin/deadeye

sudo make install       # /usr/local/bin/deadeye + fish completions + /etc/deadeye
make install-user       # no root: ~/.local/bin/deadeye + ~/.config/deadeye/config.toml
fish_add_path -U ~/.local/bin   # if ~/.local/bin is not in PATH yet
```

Removal: `sudo make uninstall` or `make uninstall-user`.

## Quick start

```bash
deadeye                          # interactive TUI
deadeye --once --top 15          # one snapshot for scripts and cron
deadeye --daemon                 # background mode with the config rules
deadeye --init-config ~/.config/deadeye/config.toml   # example config
deadeye --print-config           # which config was found and what applies
``
 Key hotkeys
 
 Tab/1-9/0 — tabs · ↑↓ j k — navigate · Enter/←→ — tree · F9 — Smart Kill · F7/F8 — renice · f — filter · / — search · a — ask AI · ?  — help · q — quit.
