package groups

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"deadeye/internal/proc"
)

type Kind string

const (
	Telemetry Kind = "telemetry"
	Browser   Kind = "browser"
	Messenger Kind = "messenger"
	Media     Kind = "media"
	Gaming    Kind = "gaming"
	Build     Kind = "build"
	Office    Kind = "office"
	Network   Kind = "network"
	Container Kind = "container"
	Editor    Kind = "editor"
	Terminal  Kind = "terminal"
	System    Kind = "system"
	Other     Kind = "other"
)

type Category struct {
	Kind Kind

	Title string

	Purpose string

	Danger string

	Blocked bool

	Patterns []string
}

var catalog = []Category{
	{
		Kind:    Telemetry,
		Title:   "Telemetry and indexing",
		Purpose: "crash reports, usage statistics, file indexers",
		Danger:  "apps may restart their crash handlers; the file index will need rebuilding",
		Patterns: []string{
			"crashpad", "crashpad-handler", "breakpad", "abrt", "abrt-applet",
			"abrt-dump-journal-core", "whoopsie", "apport", "apport-gtk",
			"telemetry", "tracker-miner-fs", "tracker-miner-rss", "tracker-extract",
			"tracker3", "baloo_file", "baloo_file_extractor", "zeitgeist",
			"kactivitymanagerd", "gsd-housekeeping", "usage", "analytics",
			"metrics", "snapd-session-agent",
		},
	},
	{
		Kind:    Browser,
		Title:   "Browsers",
		Purpose: "all browser processes: tabs, GPU, network, extensions",
		Danger:  "unsaved forms and tabs will close; the session usually restores on next launch",
		Patterns: []string{
			"chromium", "chrome", "google-chrome", "ungoogled-chromium",
			"chromedriver", "firefox", "librewolf", "waterfox", "palemoon",
			"seamonkey", "brave", "vivaldi", "opera", "msedge", "microsoft-edge",
			"epiphany", "konqueror", "falkon", "qutebrowser", "luakit", "nyxt",
			"floorp", "zen", "torbrowser", "tor-browser", "webcontent",
			"privmxn", "WebKitNetworkProcess", "WebKitWebProcess",
		},
	},
	{
		Kind:    Messenger,
		Title:   "Messengers and calls",
		Purpose: "chats, voice channels, video calls",
		Danger:  "unsent messages and the current call will drop",
		Patterns: []string{
			"telegram", "telegram-desktop", "tdesktop", "ayugram", "kutegram",
			"unigram", "signal", "signal-desktop", "whatsapp", "discord",
			"slack", "viber", "skype", "skypeforlinux", "element", "element-desktop",
			"fractal", "neochat", "nheko", "dino", "hexchat", "mumble", "teams",
			"zoom", "vkmessenger", "vkteams", "wire", "session-desktop",
		},
	},
	{
		Kind:    Media,
		Title:   "Music and video",
		Purpose: "media players",
		Danger:  "playback will stop",
		Patterns: []string{
			"spotify", "spotifyd", "vlc", "mpv", "audacious", "clementine",
			"strawberry", "elisa", "rhythmbox", "deadbeef", "cmus", "ncmpcpp",
			"lollypop", "amberol", "musikcube", "quodlibet", "sayonara",
			"celluloid", "smplayer", "haruna", "totem", "dragon", "kmplayer",
			"spotify-tray", "playerctl",
		},
	},
	{
		Kind:    Gaming,
		Title:   "Games and launchers",
		Purpose: "Steam, Lutris, Wine/Proton, emulators, overlays",
		Danger:  "an unfinished game session: progress may be lost and anti-cheat may flag the run",
		Patterns: []string{
			"steam", "steamwebhelper", "steamos", "steam-runtime", "lutris",
			"heroic", "gamescope", "gamemode", "mangohud", "proton", "wine",
			"wineserver", "wineloader", "vkd3d", "dxvk", "retroarch", "dolphin-emu",
			"rpcs3", "pcsx2", "citra", "yuzu", "ryujinx", "minecraft",
			"prismlauncher", "bottles", "mumble-overlay", "heroic-launcher",
		},
	},
	{
		Kind:    Build,
		Title:   "Builds and compilers",
		Purpose: "running compilations, linking, build package managers",
		Danger:  "an unfinished build: the cache may be incomplete, but the next run usually rebuilds",
		Patterns: []string{
			"cc1", "cc1plus", "gcc", "g++", "clang", "clang++", "rustc", "cargo",
			"ld", "ld.gold", "ld.lld", "lld", "gold", "make", "gmake", "ninja",
			"cmake", "meson", "gradle", "mvn", "javac", "kotlinc", "tsc",
			"esbuild", "webpack", "vite", "rollup", "pnpm", "yarn", "npm",
			"ccache", "sccache", "distcc", "zig", "ghc", "cabal", "dotnet",
			"msbuild", "bazel", "buck", "gyp", "compile", "link", "go-build",
			"asm", "lto1", "collect2",
		},
	},
	{
		Kind:    Office,
		Title:   "Documents and graphics",
		Purpose: "office suites, image and 3D editors, readers",
		Danger:  "unsaved documents will be lost — the most dangerous group after editors",
		Patterns: []string{
			"libreoffice", "soffice", "onlyoffice", "thunderbird", "okular",
			"evince", "zathura", "gimp", "inkscape", "krita", "blender",
			"obsidian", "notion", "joplin", "anki", "calibre", "dbeaver",
			"postman", "drawio", "scribus", "darktable", "rawtherapee",
			"kdenlive", "shotcut", "handbrake", "audacity",
		},
	},
	{
		Kind:    Network,
		Title:   "VPN and network tunnels",
		Purpose: "VPN clients, tunnels, proxies",
		Danger:  "connection drop; with a kill-switch on, the network may go down entirely",

		Blocked: true,
		Patterns: []string{
			"mullvad", "mullvad-daemon", "wireguard", "wireguard-go", "wg-quick",
			"openvpn", "amneziavpn", "amnezia", "awg", "tailscale", "tailscaled",
			"zerotier", "protonvpn", "nordvpn", "openfortivpn", "strongswan",
			"charon", "i2pd", "tor", "v2ray", "xray", "sing-box", "shadowsocks",
			"outline", "hysteria", "naiveproxy", "privoxy", "squid", "clash",
		},
	},
	{
		Kind:    Container,
		Title:   "Containers and VMs",
		Purpose: "Docker, Podman, QEMU, libvirt, distrobox",
		Danger:  "unsaved data may live inside: a DB container should be stopped properly, not by signal",
		Patterns: []string{
			"docker", "dockerd", "podman", "containerd", "buildah", "lxc",
			"qemu", "qemu-system", "virt-manager", "libvirt", "virtiofsd",
			"distrobox", "toolbox", "flatpak-spawn", "bwrap",
		},
	},
	{
		Kind:    Editor,
		Title:   "Editors and IDEs",
		Purpose: "code editors and development environments",
		Danger:  "unsaved code will be lost; kill only if you are sure everything is saved",
		Patterns: []string{
			"code", "code-oss", "vscode", "vscodium", "codium", "idea",
			"pycharm", "goland", "clion", "webstorm", "rubymine", "rider",
			"datagrip", "phpstorm", "sublime_text", "atom", "zed", "lapce",
			"nvim", "neovim", "vim", "emacs", "helix", "micro", "geany",
			"kate", "mousepad", "pluma", "jetbrains",
		},
	},
	{
		Kind:    Terminal,
		Title:   "Terminals and shells",
		Purpose: "terminal emulators and the shells running inside them",
		Danger:  "other tasks and unsaved work may be running in these windows; killing would take the program down too if it runs in one of them",

		Blocked: true,
		Patterns: []string{
			"kitty", "alacritty", "wezterm", "foot", "konsole", "gnome-terminal",
			"xterm", "urxvt", "rxvt", "terminator", "tilix", "guake", "yakuake",
			"st", "ghostty", "contour", "hyper", "cool-retro-term", "sakura",
			"lxterminal", "xfce4-terminal", "mate-terminal", "deepin-terminal",
			"fish", "bash", "zsh", "nu", "elvish", "xonsh", "tcsh", "csh",
			"kitten", "tmux", "screen", "zellij", "abduco",
		},
	},
	{
		Kind:    System,
		Title:   "System services",
		Purpose: "init, D-Bus, network, audio, compositor, display manager",
		Danger:  "killing breaks the session: audio, network or display goes away, unsaved work in all apps is lost",
		Blocked: true,
		Patterns: []string{
			"systemd", "dbus", "dbus-broker", "dbus-daemon", "NetworkManager",
			"wpa_supplicant", "iwd", "ModemManager", "polkit", "udevd",
			"systemd-udevd", "journald", "logind", "machined", "resolved",
			"timesyncd", "networkd", "sddm", "gdm", "lightdm", "lxdm", "ly",
			"hyprland", "kwin", "sway", "mutter", "labwc", "wlroots", "Xorg",
			"Xwayland", "xinit", "startx", "start-hyprland", "pipewire",
			"pulseaudio", "wireplumber", "pipewire-pulse", "rtkit", "sshd",
			"cron", "cronie", "atd", "upower", "accounts-daemon", "kthreadd",
			"bluetoothd", "cupsd", "avahi", "agetty", "login", "xdg-desktop-portal",
			"gpg-agent", "ssh-agent", "ananicy", "hypridle", "hyprlock",
			"hyprpaper", "waybar", "dunst", "mako", "swaync", "krunner",
			"plasmashell", "gnome-shell", "ydotoold", "keyring", "firewalld",
			"nftables", "systemd-timesyncd", "systemd-userdbd", "systemd-oomd",
			"systemd-journald", "systemd-logind", "agetty", "getty",
		},
	},
	{
		Kind:    Other,
		Title:   "Other",
		Purpose: "processes that fit no category",
		Danger:  "the group is heterogeneous: killing it in one action is pointless and dangerous, pick a specific process",
		Blocked: true,
	},
}

func init() {

	for i := range catalog {
		for j, pat := range catalog[i].Patterns {
			catalog[i].Patterns[j] = strings.ToLower(pat)
		}
	}
}

func Catalog() []Category {
	out := make([]Category, len(catalog))
	copy(out, catalog)
	return out
}

type Member struct {
	PID         int
	PPID        int
	Name        string
	Cmdline     string
	User        string
	UID         int
	RSSKiB      int64
	CPUPercent  float64
	Threads     int64
	Descendants int

	DescendantPIDs []int
	StartTime      time.Time

	Protected bool

	Why string
}

type Group struct {
	Category
	Members []Member

	Procs          int
	RSSKiB         int64
	CPUPercent     float64
	Killable       int
	ProtectedCount int

	Empty bool
}

func (g Group) KillProcs() int {
	seen := make(map[int]bool, len(g.Members)*2)
	for _, m := range g.Targets() {
		seen[m.PID] = true
		for _, d := range m.DescendantPIDs {
			seen[d] = true
		}
	}
	return len(seen)
}

func (g Group) Targets() []Member {
	out := make([]Member, 0, len(g.Members))
	for _, m := range g.Members {
		if !m.Protected {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Descendants < out[j].Descendants
	})
	return out
}

type Protection struct {
	self      int
	ancestors map[int]bool
	kernel    map[int]bool
	extra     map[int]string
}

func NewProtection(list []proc.Snapshot) Protection {
	return NewProtectionFor(os.Getpid(), list)
}

func NewProtectionFor(self int, list []proc.Snapshot) Protection {
	byPID := make(map[int]proc.Snapshot, len(list))
	for _, s := range list {
		byPID[s.PID] = s
	}
	p := Protection{
		self:      self,
		ancestors: make(map[int]bool),
		kernel:    make(map[int]bool, len(list)/4),
		extra:     make(map[int]string),
	}
	cur := p.self
	for i := 0; i < 64; i++ {
		s, ok := byPID[cur]
		if !ok {
			break
		}
		if s.PPID <= 0 || s.PPID == s.PID || p.ancestors[s.PPID] {
			break
		}
		p.ancestors[s.PPID] = true
		cur = s.PPID
	}
	for _, s := range list {
		if s.Kernel || s.PID == 2 || s.PPID == 2 {
			p.kernel[s.PID] = true
		}
	}
	return p
}

func (p Protection) Protect(pid int, why string) {
	if p.extra == nil {
		p.extra = make(map[int]string)
	}
	p.extra[pid] = why
}

func (p Protection) Check(s proc.Snapshot) (bool, string) {
	switch {
	case s.PID == p.self:
		return true, "this is Deadeye itself"
	case p.ancestors[s.PID]:
		return true, "in Deadeye's parent chain: killing would take the program down too"
	case s.PID == 1:
		return true, "init: the system cannot live without it"
	case p.kernel[s.PID]:
		return true, "kernel thread: user signals have no effect"
	case p.extra[s.PID] != "":
		return true, p.extra[s.PID]
	}
	return false, ""
}

func Classify(list []proc.Snapshot, prot Protection) []Group {
	return ClassifyCached(nil, list, prot)
}

func ClassifyCached(cache map[string]Kind, list []proc.Snapshot, prot Protection) []Group {
	desc := descendants(list)

	out := make([]Group, 0, len(catalog))
	byKind := make(map[Kind]int, len(catalog))
	for i, c := range catalog {
		byKind[c.Kind] = i
		out = append(out, Group{Category: c, Empty: true})
	}

	for _, s := range list {
		cat, ok := classifyCached(cache, s)
		switch {
		case s.Kernel || s.PID == 2 || s.PPID == 2:

			cat, ok = systemCategory(), true
		case !ok:
			cat = catalog[len(catalog)-1]
		}
		g := &out[byKind[cat.Kind]]
		m := Member{
			PID:            s.PID,
			PPID:           s.PPID,
			Name:           s.DisplayName(),
			Cmdline:        s.Cmdline,
			User:           s.User,
			UID:            s.UID,
			RSSKiB:         s.RSSKiB,
			CPUPercent:     s.CPUPercent,
			Threads:        s.Threads,
			Descendants:    len(desc[s.PID]),
			DescendantPIDs: desc[s.PID],
			StartTime:      s.StartTime,
		}
		if blocked, why := prot.Check(s); blocked {
			m.Protected = true
			m.Why = why
		} else if cat.Blocked {

			m.Protected = true
			m.Why = "group " + cat.Title + " cannot be killed in one action"
		}
		g.Members = append(g.Members, m)
		g.Empty = false
	}

	for i := range out {
		g := &out[i]

		sort.SliceStable(g.Members, func(a, b int) bool {
			if g.Members[a].RSSKiB != g.Members[b].RSSKiB {
				return g.Members[a].RSSKiB > g.Members[b].RSSKiB
			}
			return g.Members[a].PID < g.Members[b].PID
		})
		for _, m := range g.Members {
			g.Procs++
			g.RSSKiB += m.RSSKiB
			g.CPUPercent += m.CPUPercent
			if m.Protected {
				g.ProtectedCount++
			} else {
				g.Killable++
			}
		}
	}
	return out
}

func Summaries(gs []Group) []Group {
	out := make([]Group, 0, len(gs))
	for _, g := range gs {
		if !g.Empty {
			out = append(out, g)
		}
	}
	return out
}

func systemCategory() Category {
	for _, c := range catalog {
		if c.Kind == System {
			return c
		}
	}
	return catalog[len(catalog)-1]
}

func classifyCached(cache map[string]Kind, s proc.Snapshot) (Category, bool) {
	if cache == nil {
		return classifyOne(s)
	}
	key := matchTokens(s).key()
	if k, ok := cache[key]; ok {
		if k == Other {
			return Category{}, false
		}
		for _, c := range catalog {
			if c.Kind == k {
				return c, true
			}
		}
	}
	cat, ok := classifyOne(s)
	cache[key] = cat.Kind
	return cat, ok
}

func classifyOne(s proc.Snapshot) (Category, bool) {
	toks := matchTokens(s)
	if len(toks.names) == 0 && len(toks.args) == 0 {
		return Category{}, false
	}
	for _, c := range catalog {
		for _, p := range c.Patterns {
			for _, t := range toks.names {
				if matchToken(t, p) {
					return c, true
				}
			}
			for _, t := range toks.args {
				if t == p {
					return c, true
				}
			}
		}
	}
	return Category{}, false
}

type tokenSet struct {
	names []string
	args  []string
}

func (t tokenSet) key() string {
	return strings.Join(t.names, "\x01") + "\x02" + strings.Join(t.args, "\x01")
}

func matchTokens(s proc.Snapshot) tokenSet {
	var ts tokenSet
	out := make([]string, 0, 4)
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return
		}
		if b := filepath.Base(v); b != "" && b != "." && b != "/" {
			v = b
		}
		for _, have := range out {
			if have == v {
				return
			}
		}
		out = append(out, v)
	}

	arg0 := s.Argv0
	if i := strings.IndexByte(arg0, ' '); i > 0 {
		arg0 = arg0[:i]
	}
	add(s.Name)
	add(arg0)

	ts.names = append(ts.names, out...)
	if len(out) == 0 || !isInterpreter(out[0]) {
		return ts
	}
	fields := strings.Fields(s.Cmdline)
	args := make([]string, 0, 3)
	for i := 1; i < len(fields) && i <= 3; i++ {
		if strings.HasPrefix(fields[i], "-") {
			continue
		}
		v := strings.ToLower(fields[i])
		if b := filepath.Base(v); b != "" && b != "." && b != "/" {
			v = b
		}
		args = append(args, v)
	}
	ts.args = args
	return ts
}

var interpreters = map[string]bool{
	"node": true, "nodejs": true, "deno": true, "bun": true, "npx": true,
	"tsx": true, "ts-node": true, "python": true, "python2": true,
	"python3": true, "pypy": true, "ruby": true, "perl": true, "java": true,
	"php": true, "lua": true, "rscript": true, "env": true, "dotnet": true,
}

func isInterpreter(base string) bool {

	if interpreters[base] {
		return true
	}
	for name := range interpreters {
		if strings.HasPrefix(base, name) && len(base) > len(name) && isDelim(base[len(name)]) {
			return true
		}
	}
	return false
}

func isDelim(c byte) bool {
	switch c {
	case '-', '_', '.', '/', ' ', '+', ':', ',', '@', '=', '~':
		return true
	}
	return false
}

func matchToken(tok, pat string) bool {
	if pat == "" {
		return false
	}
	if tok == pat {
		return true
	}
	for i := 0; i+len(pat) <= len(tok); i++ {
		if tok[i:i+len(pat)] != pat {
			continue
		}
		before := i == 0 || isDelim(tok[i-1])
		after := i+len(pat) == len(tok) || isDelim(tok[i+len(pat)])
		if before && after {
			return true
		}
	}
	return false
}

func descendants(list []proc.Snapshot) map[int][]int {
	kids := make(map[int][]int, len(list))
	seen := make(map[int]bool, len(list))
	for _, s := range list {
		seen[s.PID] = true
	}
	for _, s := range list {
		if s.PPID > 0 && s.PPID != s.PID && seen[s.PPID] {
			kids[s.PPID] = append(kids[s.PPID], s.PID)
		}
	}
	out := make(map[int][]int, len(list))
	busy := make(map[int]bool, len(list))
	var walk func(pid int, acc *[]int, depth int)
	walk = func(pid int, acc *[]int, depth int) {
		if depth > 32 || busy[pid] {
			return
		}
		busy[pid] = true
		defer delete(busy, pid)
		for _, c := range kids[pid] {
			*acc = append(*acc, c)
			walk(c, acc, depth+1)
		}
	}
	for _, s := range list {
		acc := []int{}
		walk(s.PID, &acc, 0)
		if len(acc) > 0 {
			out[s.PID] = acc
		}
	}
	return out
}
