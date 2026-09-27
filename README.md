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
Build & Install

git clone https://github.com/sw1ke/deadeye && cd deadeye
make                    # bin/deadeye
sudo make install       # /usr/local/bin + fish completions + /etc/deadeye
# no root:
 make install-user
  Quick start

  deadeye                        # interactive TUI
 deadeye --once --top 15        # one snapshot for scripts/cron
 deadeye --daemon                # background mode with config rules
 Modes
 Mode Command
 Interactive deadeye
 Snapshot deadeye --once
 Foreground deadeye --foreground
 Daemon deadeye --daemon
 Key hotkeys
 Tab/1-9/0 — tabs · ↑↓ j k — navigate · Enter/←→ — tree · F9 — Smart Kill · F7/F8 — renice · f — filter · / — search · a — ask AI · ?  — help · q — quit.
