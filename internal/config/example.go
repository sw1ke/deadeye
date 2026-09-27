package config

const ExampleTOML = `# Deadeye — configuration
# Every value below matches the built-in defaults: trim the file down to what you need.

[general]
# /proc polling period in milliseconds (100..60000). At 250 ms the numbers on
# screen refresh four times a second: the list looks alive instead of "10 frames
# per second". Cheaper than it seems: the full walk of every /proc/[pid] happens
# not on every snapshot but once per deep_every (see below).
interval_ms = 250
# History depth in snapshots: for CPU, memory and RSS of each process.
history = 240
# How many goroutines read /proc/[pid] in parallel.
workers = 8
# Every Nth snapshot reads /proc/[pid] fully: status, io, limits, the fd/ walk
# and cmdline. In between, a single stat is read — it provides CPU, state,
# threads, nice and RSS, and costs several times less. Walking fd/ across
# thousands of descriptors every 250 ms is unnecessary: owner and cmdline never
# change, neither does the descriptor limit, and fd leaks develop over minutes.
# Slow fields carry over from the last full snapshot, so columns don't flicker.
# 8 snapshots at 250 ms = a full walk every 2 seconds.
deep_every = 8
# Whether to show kernel threads ([kworker/0:1], [migration/0], etc.).
include_kernel_threads = false
# -1 = all users; otherwise only processes with this uid (0 = root).
uid_filter = -1

[anomaly]
# --- Hung: high CPU without disk I/O ---
# Load threshold, % of a single core.
hung_cpu_percent = 95.0
# How many seconds this must last continuously.
hung_seconds = 30
# Block I/O that still counts as "silence", bytes/s.
hung_max_io_bytes_per_sec = 4096

# --- Memory leak: linear RSS growth ---
# Observation window in snapshots (60 snapshots at 1 s = a minute).
leak_window = 60
# Minimum growth slope, KiB/s.
leak_min_slope_kib_per_sec = 512
# Maximum relative drop from the peak: if memory was once freed noticeably,
# it's allocator noise, not a leak.
leak_max_drop_ratio = 0.05
# Processes below this RSS are not analyzed (65536 KiB = 64 MiB).
leak_min_rss_kib = 65536
# Required quality of the linear fit (0..1).
leak_min_r2 = 0.80

# --- Other ---
# Fraction of open descriptors relative to the soft limit at which we raise an alarm.
fd_warn_ratio = 0.80
# How many seconds a process must linger as a zombie to become an anomaly.
zombie_seconds = 60
# Storm block I/O threshold, MiB/s (0 = don't check).
io_storm_mb_per_sec = 200

[actions]
# nice step applied by F7/F8.
renice_step = 5
# Wait after SIGTERM in a Smart Kill.
graceful_timeout_ms = 5000
# Whether to send SIGABRT for a core dump before SIGKILL.
coredump = true
core_wait_ms = 2000
final_wait_ms = 2000

[daemon]
# Log file for daemon mode (empty = stdout/stderr only).
log_file = ""
# Level: info | warn | error.
log_level = "info"
# PID file (empty = don't create one).
pid_file = ""
# Log rotation: once exceeded, the file is renamed to <log_file>.1 (0 = no rotation).
max_log_mb = 10

# Automatically lower the priority of anomalous processes.
auto_renice = false
auto_renice_delta = 10

# Automatically kill processes that stay anomalous for more than N seconds.
# 0 = automatic kill disabled (recommended to start with).
auto_kill_after_sec = 0
auto_kill_kinds = ["hung", "memleak"]

# Restrict automatic actions to your own processes (the current user's uid).
own_processes_only = true

[ui]
# Screen refresh rate (bubbletea renderer). Data is still collected
# independently, on the general.interval_ms period.
fps = 60
# Initial sort: total | pid | user | name | cpu | mem | delta | io | fd | age | nice | state | none.
# "total" — combined consumption: CPU% + 2 × the share of RAM, the Windows
# Task Manager way. For tree branches both values are the subtree sums.
sort_column = "total"
sort_desc = true
# Show the full command line instead of the process name.
show_cmdline = false
# How many events to keep in the UI log.
max_log_lines = 200
mouse_support = true
# Show processes as a tree: the root is the application, children are collapsed,
# the "chromium (39)" row carries the sums for the whole subtree. Enter expands
# a branch.
# false — a plain flat list, like top.
tree_view = true
# Your own processes above system ones. People open the list for their own
# applications; root services are just background noise that gets in the way of
# finding them. The split is stable: within your own group the sort column still
# defines the order, and the hottest of your processes is still first among
# yours. The u key toggles it on the fly.
user_first = true
# Sort by the smoothed value of volatile metrics (CPU%, I/O, ΔRSS).
# Instant CPU% changes on every snapshot, and without smoothing the rows keep
# reshuffling — the list "jumps". Smoothing affects only the ORDER: each row
# still shows the true instantaneous number.
# Also, while at least one branch is expanded, the order of roots is not
# revisited at all: the user is looking inside a branch, and teleporting the
# list right under the cursor only gets in the way.
smooth_sort = true
# How often the order of ROOTS may be revisited, ms. Neighbors overtake each
# other on every tick, and without a settling pause the list jumps endlessly;
# the values in the rows still update immediately. 0 — sort on every snapshot.
# Changing the sort column or the filter unfreezes the order at once.
sort_settle_ms = 2000
# Session wrappers hidden from the process tree. These processes are not shown
# at all, and their children are promoted to roots: without this the whole
# desktop nests inside "start-hyprland"/"gnome-shell" and the tree collapses
# into a single branch. Matched case-insensitively against the process name.
transparent_names = ["hyprland", "start-hyprland"]

[hung]
# Thresholds for the "Hung" tab: how many seconds a process must spend in a
# suspicious state to make the list. Values that are too low turn the tab into
# noise: a short block on the disk is business as usual.
# D — uninterrupted kernel sleep (waiting for I/O).
io_block_sec = 10
# R — the process sits at 100% CPU for a long time and barely reads/writes.
cpu_burn_sec = 30
# Z — zombie: it exited on its own, but the parent never reaped its status.
zombie_sec = 60
# T — stopped by a signal (usually a forgotten Ctrl+Z).
stopped_sec = 120
# Load at which a process counts as "saturating a core" without an anomaly.
cpu_burn_percent = 90.0

# --- Security (the "Security" tab, key 6) ---
#
# The check runs ON DEMAND: the tab scans nothing in the background until r is
# pressed. Otherwise walking the autostart entries and /proc/net would cost a
# noticeable fraction of a second every 250 ms.
[security]
enabled = true
# Walk autostart entries: ~/.config/autostart, user and system systemd units,
# hypr, fish, .bashrc, cron.
scan_autostart = true
# Parse /proc/net: who listens on ports and whether the socket is visible from the network.
scan_network = true
# Compute SHA-256 of suspicious executables. The hash is needed for the
# external reputation check and to tell "the same file" from "a similar one".
hash_files = true
# Files larger than this are not hashed: reading gigabytes for a check makes no sense.
max_hash_bytes = 33554432
# Ask pacman which package a system file belongs to. A file in
# /etc/systemd/system with no owning package is a common sign of persistence.
check_packages = true
# Directories from which legitimate programs do not normally run.
suspicious_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/run/user", "/mnt", "/media"]
# Ports on which miners usually listen.
miner_ports = [3333, 4444, 5555, 7777, 14444, 14433, 45700, 8080]

# External hash reputation check via the DeepSeek API.
#
# Disabled by default: without a key the program must not go anywhere.
# Cost is squeezed from every side — first the on-disk cache, then the daily
# limit, and only then a request. File contents are never sent out: only the
# hash, path, size and the text of local evidence.
[security.deepseek]
enabled = false
api_key = ""
endpoint = "https://api.deepseek.com"
model = "deepseek-chat"
# Response length: four lines of verdict, no more is needed.
max_tokens = 260
# Zero: we need facts, not reasoning that costs money too.
temperature = 0.0
timeout_ms = 45000
# How many requests per day are allowed at all. The limit is stored in the
# cache, so restarting the program does not reset it.
max_requests_per_day = 20
# Findings of which level and above are worth asking about (1 note, 2 low,
# 3 medium, 4 high, 5 critical).
min_level = 3
# Response cache. Empty value — ~/.cache/deadeye/hashes.json.
cache_path = ""
cache_days = 30

# --- Local language model (the "AI" tab, key 4) ---
#
# The model is invoked ONLY on an explicit keypress: no background requests and
# no "explain every anomaly automatically". Without a running Ollama the
# program works as usual; the tab only hints at what to install.
[ai]
enabled = true
# Address of the local Ollama server.
endpoint = "http://127.0.0.1:11434"
# A small model: 1.5B answers within seconds and takes about a gigabyte.
model = "qwen2.5:1.5b"
# Response length limit in tokens. More means longer reasoning, which is
# usually not needed for diagnostics.
max_tokens = 220
# Temperature 0.2: the explanation should be predictable, not creative.
temperature = 0.2
# How long to wait for an answer, ms. The first request after the weights load takes longer.
timeout_ms = 90000
# "0" — unload the model from memory right after the answer. That way it does
# not hold a gigabyte and a half between requests.
keep_alive = "0"
# The model's system prompt. An empty string means use the built-in one.
system_prompt = ""

# --- Automatic reaction rules (used by the daemon only) ---
#
# match_name and match_cmdline are regular expressions (Go regexp syntax);
# when a field is unset it does not constrain the match.
# match_uid — the numeric UID of the owner: 0 = root only, 1000 = only your
#   user. If the match_uid line is omitted entirely, the rule applies to
#   processes of any owner (this is NOT the same as match_uid = 0).
# anomaly: hung | memleak | fdleak | zombie | iostorm | any
# action:  renice | kill | log | ignore
# nice_delta — the step for action = "renice" (0 = use daemon.auto_renice_delta).
# kill_tree = true for action = "kill" — terminate the process together with
#   all its descendants (leaves first, root last). Needed where the parent
#   restarts a killed process: browsers, build supervisors, tor.
#   Defaults to false — only the process itself is terminated.
# max_times — how many times a rule may fire on one process (0 = unlimited);
#   cooldown_sec — the minimum pause between firings.
# enabled = false — the rule stays in the config but is not applied.
#
# Order matters: the FIRST matching rule handles the anomaly.
# Rules do not override Deadeye's protection: PID 1 and Deadeye itself are
# never touched, and with own_processes_only = true other users' processes are
# unreachable in principle.

[[rule]]
name = "lower the priority of hung builders"
match_name = "^(cc1|rustc|go|make|ninja)$"
anomaly = "hung"
action = "renice"
nice_delta = 10
max_times = 1
cooldown_sec = 300

[[rule]]
name = "take down hung builds entirely"
match_name = "^(make|ninja|cargo)$"
anomaly = "hung"
action = "kill"
kill_tree = true   # otherwise cc1 and rustc keep running without their parent
cooldown_sec = 600

[[rule]]
name = "do not touch system services"
match_cmdline = "/usr/lib/systemd/"
anomaly = "any"
action = "ignore"

[[rule]]
name = "log leaks in browsers"
match_name = "(chrome|firefox|Web Content)"
anomaly = "memleak"
action = "log"
cooldown_sec = 600

[[rule]]
name = "example of a disabled rule"
match_name = "example"
match_uid = 1000
anomaly = "any"
action = "kill"
enabled = false
`
