# fish completion for deadeye.
#
# Installation:
#   make install-user      → ~/.config/fish/completions/deadeye.fish
#   sudo make install      → /usr/share/fish/vendor_completions.d/deadeye.fish
#
# The file is named after the command: fish picks the completion by name.
# Only the flags the program actually accepts are described:
# the list is checked against `deadeye --help`.

# Modes
complete -c deadeye -l once -d 'One system snapshot to stdout and exit'
complete -c deadeye -l foreground -d 'Background logic without the TUI, log to stdout'
complete -c deadeye -l daemon -d 'Detach into the background and apply config rules'
complete -c deadeye -l version -d 'Show version and exit'
complete -c deadeye -l print-config -d 'Print the effective config (TOML)'
complete -c deadeye -l flat -d 'Flat list instead of the tree (overrides ui.tree_view)'

# Flags with values
complete -c deadeye -l config -r -F -d 'Path to the config (TOML or JSON)'
complete -c deadeye -l init-config -r -F -d 'Create an example config and exit'
complete -c deadeye -l log -r -F -d 'Action log file'
complete -c deadeye -l pid-file -r -F -d 'File for the background process PID'
complete -c deadeye -l top -r -d 'How many processes to print in --once (default 20)'
complete -c deadeye -l uid -r -d 'Monitor only this UID (-1 — all)'
complete -c deadeye -l interval -r -a '200ms 500ms 1s 5s' -d 'Metric collection period'
complete -c deadeye -l history -r -d 'History depth for trends, in snapshots'
complete -c deadeye -l workers -r -d 'How many goroutines read /proc in parallel'

# Common UID values: own and root
complete -c deadeye -l uid -r -a '(id -u)	"own UID"
0	"root"'
