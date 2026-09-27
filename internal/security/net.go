package security

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"deadeye/internal/proc"
)

type Listener struct {
	Proto   string
	Local   string
	Port    int
	Inode   uint64
	PID     int
	Process string
	Exe     string

	Public bool
}

func (s *Scanner) ScanNetwork(procs []proc.Snapshot) ([]Finding, []Listener) {
	if !s.cfg.Enabled || !s.cfg.ScanNetwork {
		return nil, nil
	}

	inodeOwner := s.buildInodeIndex(procs)
	byPID := make(map[int]proc.Snapshot, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}

	var listeners []Listener
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		listeners = append(listeners, s.readNetProto(proto, inodeOwner, byPID)...)
	}

	findings := make([]Finding, 0, 4)
	unknownPublic := 0
	for _, l := range listeners {
		if l.PID == 0 && l.Public {
			unknownPublic++
			continue
		}
		if l.PID == 0 {
			continue
		}
		if s.isMinerPort(l.Port) && l.Public {
			findings = append(findings, Finding{
				Level: LevelCritical, Kind: "listens on a pool port",
				Subject: fmt.Sprintf("%s:%d", l.Proto, l.Port), PID: l.PID,
				Detail: fmt.Sprintf("%s (PID %d) listens on %s on all interfaces",
					l.Process, l.PID, l.Local),
				Evidence: []string{
					fmt.Sprintf("port %d is on the list of typical mining pool ports", l.Port),
					"owner: " + l.Exe,
				},
				Action: "kill the process and check the autostart entry that started it",
			})
			continue
		}
		if l.Public && s.suspiciousDir(l.Exe) {
			findings = append(findings, Finding{
				Level: LevelHigh, Kind: "network from a temp directory",
				Subject: fmt.Sprintf("%s:%d", l.Proto, l.Port), PID: l.PID,
				Path: l.Exe,
				Detail: fmt.Sprintf("%s listens on %s but runs from %s",
					l.Process, l.Local, filepath.Dir(l.Exe)),
				Evidence: []string{
					"socket is reachable from the network (not 127.0.0.1)",
					"the executable sits in a writable directory: " + l.Exe,
				},
				Action: "close the port (firewall) and find out who started the process",
			})
		}
	}
	if unknownPublic > 0 {
		findings = append(findings, Finding{
			Level: LevelNote, Kind: "no permission for the socket owner",
			Subject: fmt.Sprintf("%d listening sockets", unknownPublic),
			Detail:  "the owning process could not be determined for some sockets",
			Evidence: []string{
				"other users' /proc/[pid]/fd are not readable without root",
				"this is a permission limitation, not a sign of a problem",
			},
			Action: "run as root for the full list: pkexec deadeye",
		})
	}
	SortFindings(findings)
	return findings, listeners
}

func (s *Scanner) readNetProto(proto string, owners map[uint64]int,
	byPID map[int]proc.Snapshot) []Listener {

	f, err := os.Open(s.procPath("net", proto))
	if err != nil {
		return nil
	}
	defer f.Close()

	udp := strings.HasPrefix(proto, "udp")
	var out []Listener
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		if !udp && fields[3] != "0A" {
			continue
		}
		addr, port := parseNetAddr(fields[1])
		if port == 0 {
			continue
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		l := Listener{
			Proto: proto, Local: net.JoinHostPort(addr, strconv.Itoa(port)),
			Port: port, Inode: inode, Public: isPublicAddr(addr),
		}
		if pid, ok := owners[inode]; ok {
			l.PID = pid
			if p, ok := byPID[pid]; ok {
				l.Process = p.DisplayName()
			}
			l.Exe = s.exePath(pid)
			l.Exe = strings.TrimSuffix(l.Exe, " (deleted)")
		}
		out = append(out, l)
	}
	return out
}

func (s *Scanner) buildInodeIndex(procs []proc.Snapshot) map[uint64]int {
	out := make(map[uint64]int, 256)
	for _, p := range procs {
		dir := s.procPath(strconv.Itoa(p.PID), "fd")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			target, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
			if err != nil {
				continue
			}
			if _, ok := out[inode]; !ok {
				out[inode] = p.PID
			}
		}
	}
	return out
}

func parseNetAddr(field string) (string, int) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0
	}
	switch len(raw) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", raw[3], raw[2], raw[1], raw[0]), int(port)
	case 16:
		fixed := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			for b := 0; b < 4; b++ {
				fixed[w*4+b] = raw[w*4+3-b]
			}
		}
		return fixed.String(), int(port)
	}
	return "", int(port)
}

func isPublicAddr(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() {
		return false
	}

	if ip.IsUnspecified() {
		return true
	}

	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	return true
}

func (s *Scanner) isMinerPort(port int) bool {
	for _, p := range s.cfg.MinerPorts {
		if p == port {
			return true
		}
	}
	return false
}
