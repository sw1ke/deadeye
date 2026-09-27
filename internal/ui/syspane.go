package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/system"
)

type sysSection struct {
	title string
	start int
	count int
}

func sysRegistry() ([]sysSection, []system.Spec) {
	groups := []struct {
		title string
		items []system.Spec
	}{
		{
			title: "SUMMARY · no root",
			items: []system.Spec{
				{Verb: system.VerbInfo, Program: "systemd-analyze", Args: []string{"blame"}, Title: "Slowest units at boot", Hint: "which units slowed the start", Timeout: 25 * time.Second},
				{Verb: system.VerbInfo, Program: "ss", Args: []string{"-tulpen"}, Title: "Listening ports", Hint: "who opened the sockets", Timeout: 8 * time.Second},
				{Verb: system.VerbInfo, Program: "loginctl", Args: []string{"list-sessions"}, Title: "User sessions", Hint: "who is in the system right now", Timeout: 8 * time.Second},
				{Verb: system.VerbInfo, Program: "pacman", Args: []string{"-Qdt"}, Title: "Orphaned packages", Hint: "left over after removals", Timeout: 20 * time.Second},
				{Verb: system.VerbInfo, Program: "journalctl", Args: []string{"-p", "3", "-b", "--no-pager"}, Title: "Errors from this boot", Hint: "level err and above", Timeout: 20 * time.Second},
			},
		},
		{
			title: "POWER",
			items: []system.Spec{
				{Verb: system.VerbPower, Program: "loginctl", Args: []string{"lock-session"}, Title: "Lock the screen", Hint: "runs immediately, without a password", Timeout: 8 * time.Second},
				{Verb: system.VerbPower, Program: "systemctl", Args: []string{"suspend"}, Title: "Suspend (to RAM)", Hint: "go to sleep", Confirm: "this machine has a known kernel bug in xhci_hcd 0000:11:00.0 (hcd_pci_suspend -16): sleep may hang. Continue?", Timeout: 30 * time.Second},
				{Verb: system.VerbPower, Program: "systemctl", Args: []string{"hibernate"}, Title: "Hibernate (to disk)", Hint: "state is written to disk", Confirm: "save memory to disk and power off", Timeout: 60 * time.Second},
				{Verb: system.VerbPower, Program: "systemctl", Args: []string{"hybrid-sleep"}, Title: "Hybrid sleep", Hint: "RAM + disk: wakes quickly but survives power loss", Confirm: "enter hybrid sleep", Timeout: 60 * time.Second},
				{Verb: system.VerbPower, Program: "systemctl", Args: []string{"reboot"}, Title: "Reboot", Confirm: "the system will reboot immediately", Timeout: 30 * time.Second},
				{Verb: system.VerbPower, Program: "systemctl", Args: []string{"poweroff"}, Title: "Power off", Confirm: "the system will power off immediately", Timeout: 30 * time.Second},
			},
		},
		{
			title: "SERVICES",
			items: []system.Spec{
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"restart", "NetworkManager"}, Title: "Restart NetworkManager", Hint: "the network will reconnect for a moment", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"restart", "bluetooth"}, Title: "Restart Bluetooth", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"restart", "cups"}, Title: "Restart printing (CUPS)", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"restart", "sshd"}, Title: "Restart SSH server", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"restart", "pipewire"}, Title: "Restart audio (PipeWire)", Hint: "audio will drop out for a moment", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"restart", "docker"}, Title: "Restart Docker", Timeout: 60 * time.Second},
			},
		},
		{
			title: "NETWORK",
			items: []system.Spec{
				{Verb: system.VerbNet, Program: "ufw", Args: []string{"status"}, Title: "Firewall status (ufw)", Timeout: 10 * time.Second},
				{Verb: system.VerbNet, Program: "rfkill", Args: []string{"block", "wifi"}, Title: "Turn Wi-Fi off", Timeout: 10 * time.Second},
				{Verb: system.VerbNet, Program: "rfkill", Args: []string{"unblock", "wifi"}, Title: "Turn Wi-Fi on", Timeout: 10 * time.Second},
				{Verb: system.VerbNet, Program: "ufw", Args: []string{"enable"}, Title: "Enable firewall", Confirm: "ufw will turn on and may drop current connections", Timeout: 30 * time.Second},
				{Verb: system.VerbNet, Program: "ufw", Args: []string{"disable"}, Title: "Disable firewall", Confirm: "ufw will stop filtering traffic", Timeout: 30 * time.Second},
			},
		},
		{
			title: "TIME, LOCALE, HOST",
			items: []system.Spec{
				{Verb: system.VerbInfo, Program: "timedatectl", Args: []string{}, Title: "Time and timezone", Hint: "status, NTP, RTC", Timeout: 8 * time.Second},
				{Verb: system.VerbModule, Program: "timedatectl", Args: []string{"set-ntp", "true"}, Title: "Enable time sync (NTP)", Timeout: 15 * time.Second},
				{Verb: system.VerbInfo, Program: "localectl", Args: []string{}, Title: "Locale and layout", Hint: "the system's current locale", Timeout: 8 * time.Second},
				{Verb: system.VerbModule, Program: "localectl", Args: []string{"set-locale", "LANG=ru_RU.UTF-8"}, Title: "Set locale ru_RU.UTF-8", Hint: "the default system language", Timeout: 15 * time.Second},
				{Verb: system.VerbInfo, Program: "hostnamectl", Args: []string{}, Title: "Hostname", Timeout: 8 * time.Second},
			},
		},
		{
			title: "MEMORY AND DISKS",
			items: []system.Spec{
				{Verb: system.VerbInfo, Program: "sysctl", Args: []string{"-n", "vm.swappiness"}, Title: "Swappiness threshold", Hint: "lower means less swapping", Timeout: 8 * time.Second},
				{Verb: system.VerbModule, Program: "sysctl", Args: []string{"-w", "vm.swappiness=10"}, Title: "Lower swappiness to 10", Hint: "swap will be used later", Timeout: 10 * time.Second},
				{Verb: system.VerbPkg, Program: "fstrim", Args: []string{"-v", "/"}, Title: "Trim SSD (fstrim /)", Hint: "restores speed after a long uptime", Timeout: 5 * time.Minute},
			},
		},
		{
			title: "SERVICES: ENABLE/DISABLE",
			items: []system.Spec{
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"enable", "--now", "bluetooth"}, Title: "Enable Bluetooth at boot", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"disable", "--now", "bluetooth"}, Title: "Disable Bluetooth and remove it from autostart", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"enable", "--now", "sshd"}, Title: "Enable SSH server at boot", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"disable", "--now", "sshd"}, Title: "Disable SSH server", Timeout: 30 * time.Second},
				{Verb: system.VerbUnit, Program: "systemctl", Args: []string{"daemon-reload"}, Title: "Reload unit files (daemon-reload)", Hint: "after editing units", Timeout: 15 * time.Second},
			},
		},
		{
			title: "KERNEL AND DRIVERS",
			items: []system.Spec{
				{Verb: system.VerbInfo, Program: "lsmod", Args: []string{}, Title: "Loaded kernel modules", Hint: "list of drivers", Timeout: 8 * time.Second},
				{Verb: system.VerbInfo, Program: "lspci", Args: []string{"-k"}, Title: "Devices and their drivers", Hint: "including the network card and «Kernel driver in use»", Timeout: 15 * time.Second},
				{Verb: system.VerbInfo, Program: "dmesg", Args: []string{"--ctime", "--level=err,warn"}, Title: "Kernel errors (dmesg)", Hint: "warn and err since boot", Timeout: 15 * time.Second},
				{Verb: system.VerbInfo, Program: "systemctl", Args: []string{"list-units", "--failed"}, Title: "Failed services", Timeout: 10 * time.Second},
				{Verb: system.VerbInfo, Program: "systemctl", Args: []string{"list-timers"}, Title: "systemd timers", Hint: "what runs on a schedule and when", Timeout: 10 * time.Second},
				{Verb: system.VerbModule, Program: "deadeye-blacklist", Args: []string{}, Title: "Blacklist driver…", Hint: "enter module name (e.g. r8169) — it will no longer load", Timeout: 10 * time.Second},
				{Verb: system.VerbModule, Program: "deadeye-unblacklist", Args: []string{}, Title: "Restore a blacklisted driver…", Hint: "enter module name", Timeout: 10 * time.Second},
			},
		},
		{
			title: "PACKAGES",
			items: []system.Spec{
				{Verb: system.VerbPkg, Program: "pacman", Args: []string{"-Syu"}, Title: "Full system upgrade", Hint: "will take a while", Confirm: "upgrades all packages; do not run a second package manager", Timeout: 15 * time.Minute},
				{Verb: system.VerbPkg, Program: "paccache", Args: []string{"-r"}, Title: "Clean the package cache", Hint: "keeps the last 3 versions", Timeout: 5 * time.Minute},
				{Verb: system.VerbPkg, Program: "paccache", Args: []string{"-ruk0"}, Title: "Remove the cache of uninstalled packages", Timeout: 5 * time.Minute},
			},
		},
	}

	sections := make([]sysSection, 0, len(groups))
	flat := make([]system.Spec, 0, 32)
	for _, g := range groups {
		start := len(flat)
		flat = append(flat, g.items...)
		sections = append(sections, sysSection{title: g.title, start: start, count: len(g.items)})
	}
	return sections, flat
}

func (m *Model) sysInit() {
	if m.sysR != nil {
		return
	}
	m.sysSections, m.sysItems = sysRegistry()
	m.sysR = system.NewRunner("", func(action, detail string) {
		m.journal.Actionf("system", 0, action, "%s", detail)
	})
}

func (m *Model) sysSelected() (system.Spec, bool) {
	if m.sysCursor < 0 || m.sysCursor >= len(m.sysItems) {
		return system.Spec{}, false
	}
	return m.sysItems[m.sysCursor], true
}

func (m *Model) sysMove(delta int) {
	if len(m.sysItems) == 0 {
		return
	}
	m.sysCursor += delta
	if m.sysCursor < 0 {
		m.sysCursor = 0
	}
	if m.sysCursor >= len(m.sysItems) {
		m.sysCursor = len(m.sysItems) - 1
	}
	if m.sysCursor < m.sysScroll {
		m.sysScroll = m.sysCursor
	}
}

func (m *Model) sysRootLine() string {
	if m.sysR != nil && m.sysR.Authorized() {
		return "root granted for this session"
	}
	return "the root password has not been entered yet"
}

func (m *Model) renderSys(h int) string {
	inner := m.width - 4
	if inner < 24 {
		inner = 24
	}
	m.sysInit()

	var b strings.Builder
	b.WriteString(clipPad(headerStyle.Render("SYSTEM")+dimStyle.Render("  ·  "+m.sysRootLine()), inner))
	b.WriteString("\n")
	b.WriteString(clipPad(dimStyle.Render(" Enter — run · y — confirm · r — refresh · C — clear"), inner))
	b.WriteString("\n")

	type row struct {
		text    string
		isItem  bool
		itemIdx int
	}
	var rows []row
	for _, sec := range m.sysSections {
		rows = append(rows, row{text: dimStyle.Render(" " + sec.title)})
		for j := 0; j < sec.count; j++ {
			idx := sec.start + j
			spec := m.sysItems[idx]
			mark := dimStyle.Render("·")
			switch {
			case spec.Confirm != "":
				mark = warnStyle.Render("!")
			case spec.Verb != system.VerbInfo:
				mark = keyStyle.Render(">")
			}
			text := "  " + mark + " " + spec.Title
			if spec.Hint != "" {
				text += dimStyle.Render("  —  " + spec.Hint)
			}
			rows = append(rows, row{text: text, isItem: true, itemIdx: idx})
		}
	}

	// Fit the result block into the pane: prefer 7 rows, shrink it when the
	// terminal is short, but always keep at least one row for the list.
	resultH := h - 3
	if resultH > 7 {
		resultH = 7
	}
	if resultH < 2 {
		resultH = 2
	}
	listH := h - resultH
	if listH < 1 {
		listH = 1
		resultH = h - listH
	}
	maxScroll := len(rows) - listH
	if m.sysScroll > maxScroll {
		m.sysScroll = maxScroll
	}
	if m.sysScroll < 0 {
		m.sysScroll = 0
	}
	end := m.sysScroll + listH
	if end > len(rows) {
		end = len(rows)
	}
	for i := m.sysScroll; i < end; i++ {
		out := clipPad(rows[i].text, inner)
		if rows[i].isItem && rows[i].itemIdx == m.sysCursor {
			out = selectedStyle.Render(out)
		}
		b.WriteString(out)
		b.WriteString("\n")
	}

	list := padToHeight(b.String(), listH, m.width)
	return list + "\n" + m.sysResultBlock(inner, resultH)
}

func (m *Model) sysResultBlock(inner, resultH int) string {
	var out strings.Builder
	switch {
	case m.sysInput:
		out.WriteString(accStyle.Render(clipTo(" "+m.sysInputAsk, inner)))
		out.WriteString("\n")
		out.WriteString(selectedStyle.Render(clipTo(" "+m.sysInputBuf+"▏", inner)))
		out.WriteString("\n")
		out.WriteString(dimStyle.Render(clipTo(" Enter — confirm · Esc — cancel", inner)))
		out.WriteString("\n")
	case m.sysBusy:
		out.WriteString(accStyle.Render(clipTo(" running…", inner)))
		out.WriteString("\n")
	case m.sysConfirm != nil:
		out.WriteString(warnStyle.Render(clipTo(" Confirm: "+m.sysConfirm.Title, inner)))
		out.WriteString("\n")
		out.WriteString(textStyle.Render(clipTo("  "+m.sysConfirm.Confirm, inner)))
		out.WriteString("\n")
		out.WriteString(dimStyle.Render(clipTo("  y — run · n / Esc — cancel", inner)))
		out.WriteString("\n")
	case m.sysHasResult:
		out.WriteString(accStyle.Render(clipTo(" "+m.sysResult.Spec.Title, inner)))
		out.WriteString("\n")
		if m.sysResult.Err != "" || m.sysResult.Code != 0 {
			out.WriteString(rowWarnStyle.Render(clipTo(fmt.Sprintf(" code %d · %s", m.sysResult.Code, m.sysResult.Err), inner)))
			out.WriteString("\n")
		} else {
			out.WriteString(dimStyle.Render(clipTo(fmt.Sprintf(" code 0 · %s", m.sysResult.Duration.Round(time.Millisecond)), inner)))
			out.WriteString("\n")
		}
		body := m.sysResult.Stdout
		if m.sysResult.Stderr != "" {
			if body != "" {
				body += "\n"
			}
			body += "stderr: " + m.sysResult.Stderr
		}

		shown := 0
		for _, ln := range strings.Split(body, "\n") {
			if shown >= resultH-3 {
				break
			}
			out.WriteString(clipTo(" "+ln, inner))
			out.WriteString("\n")
			shown++
		}
	default:
		out.WriteString(dimStyle.Render(clipTo(" Enter on a summary item shows the result without root;", inner)))
		out.WriteString("\n")
		out.WriteString(dimStyle.Render(clipTo(" items with «!» ask for confirmation; the first one asks for the root password.", inner)))
		out.WriteString("\n")
	}
	return padToHeight(out.String(), resultH, m.width)
}

func (m *Model) handleSysKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	m.sysInit()

	if m.sysInput {
		switch msg.String() {
		case "esc", "ctrl+c":
			m.sysInput = false
			m.sysInputBuf = ""
			return nil, true
		case "enter":
			name := strings.TrimSpace(m.sysInputBuf)
			m.sysInput = false
			m.sysInputBuf = ""
			if name == "" {
				m.setStatus("empty module name — cancelled", true, 4*time.Second)
				return nil, true
			}
			spec := m.sysInputSpec
			spec.Args = []string{name}
			if spec.Program == "deadeye-blacklist" {
				spec.Confirm = "blacklist driver " + name + "? It will no longer load after a reboot"
			} else {
				spec.Confirm = "restore driver " + name + " from the blacklist?"
			}
			m.sysConfirm = &spec
			return nil, true
		case "backspace":
			if r := []rune(m.sysInputBuf); len(r) > 0 {
				m.sysInputBuf = string(r[:len(r)-1])
			}
			return nil, true
		case "ctrl+u":
			m.sysInputBuf = ""
			return nil, true
		}
		if msg.Type == tea.KeyRunes {
			m.sysInputBuf += string(msg.Runes)
			return nil, true
		}
		return nil, true
	}
	if m.sysConfirm != nil {
		switch msg.String() {
		case "y":
			spec := *m.sysConfirm
			m.sysConfirm = nil
			return m.sysRunAction(spec), true
		case "n", "esc":
			m.sysConfirm = nil
			return nil, true
		}
	}
	switch msg.String() {
	case "up", "k":
		m.sysMove(-1)
		return nil, true
	case "down", "j":
		m.sysMove(1)
		return nil, true
	case "pgup", "ctrl+u":
		m.sysMove(-8)
		return nil, true
	case "pgdown", "ctrl+d":
		m.sysMove(8)
		return nil, true
	case "home", "g":
		m.sysCursor, m.sysScroll = 0, 0
		return nil, true
	case "end", "G":
		m.sysCursor = len(m.sysItems) - 1
		if m.sysCursor < 0 {
			m.sysCursor = 0
		}

		m.sysScroll = len(m.sysItems) + len(m.sysSections) + 1
		return nil, true
	case "enter":
		spec, ok := m.sysSelected()
		if !ok {
			return nil, true
		}

		if (spec.Program == "deadeye-blacklist" || spec.Program == "deadeye-unblacklist") && len(spec.Args) == 0 {
			m.sysInput = true
			m.sysInputBuf = ""
			m.sysInputSpec = spec
			if spec.Program == "deadeye-blacklist" {
				m.sysInputAsk = "module name to blacklist (e.g. r8169): "
			} else {
				m.sysInputAsk = "module name to restore: "
			}
			return nil, true
		}
		if spec.Verb == system.VerbInfo {
			return m.sysRunLocal(spec), true
		}
		if spec.Confirm != "" {
			m.sysConfirm = &spec
			return nil, true
		}
		return m.sysRunAction(spec), true
	case "r":

		if m.sysR != nil && !m.sysR.Authorized() {
			_ = m.sysR.FinishStart(nil)
		}
		return nil, true
	case "C":
		m.sysHasResult = false
		m.sysResult = system.Result{}
		return nil, true
	}
	return nil, false
}

func (m *Model) sysRunLocal(spec system.Spec) tea.Cmd {
	m.sysBusy = true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout+5*time.Second)
		defer cancel()
		res, err := system.RunLocal(ctx, spec)
		return sysResultMsg{res: res, err: err}
	}
}

func (m *Model) sysRunAction(spec system.Spec) tea.Cmd {
	m.sysBusy = true
	return func() tea.Msg {
		if m.sysR == nil || !m.sysR.Authorized() {
			return sysNeedRootMsg{spec: spec}
		}
		ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout+10*time.Second)
		defer cancel()
		res, err := m.sysR.Run(ctx, spec)
		return sysResultMsg{res: res, err: err}
	}
}

type sysResultMsg struct {
	res system.Result
	err error
}

type sysNeedRootMsg struct {
	spec system.Spec
}

type sysStartMsg struct {
	err error
}

func (m *Model) handleSysResult(msg sysResultMsg) tea.Cmd {
	m.sysBusy = false
	m.sysHasResult = true
	m.sysResult = msg.res
	if msg.err != nil && msg.res.Err == "" {
		m.sysResult.Err = msg.err.Error()
	}
	if msg.err != nil {
		m.setStatus("failed to run: "+msg.err.Error(), true, 8*time.Second)
	} else if msg.res.Code != 0 {
		m.setStatus(fmt.Sprintf("%s: exit code %d", msg.res.Spec.Title, msg.res.Code), true, 8*time.Second)
	} else {
		m.setStatus("done: "+msg.res.Spec.Title, false, 6*time.Second)
	}
	return nil
}

func (m *Model) sysNeedRoot(msg sysNeedRootMsg) tea.Cmd {
	m.sysInit()
	if m.sysR.Authorized() {
		return m.sysRunAction(msg.spec)
	}
	m.sysPending = &msg.spec
	m.setStatus("requesting root password…", false, 60*time.Second)
	return tea.ExecProcess(m.sysR.StartCmd(), func(err error) tea.Msg {
		return sysStartMsg{err: err}
	})
}

func (m *Model) sysStarted(msg sysStartMsg) tea.Cmd {
	if err := m.sysR.FinishStart(msg.err); err != nil {
		m.sysBusy = false
		m.sysPending = nil
		m.setStatus("root login failed: "+err.Error(), true, 10*time.Second)
		return nil
	}
	m.setStatus("root privileges granted for this session", false, 4*time.Second)
	if m.sysPending != nil {
		spec := *m.sysPending
		m.sysPending = nil
		return m.sysRunAction(spec)
	}
	return nil
}
