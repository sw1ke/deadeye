package system

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Verb string

const (
	VerbPower  Verb = "power"
	VerbUnit   Verb = "unit"
	VerbNet    Verb = "net"
	VerbPkg    Verb = "pkg"
	VerbModule Verb = "module"
	VerbInfo   Verb = "info"
)

type Spec struct {
	Verb    Verb
	Program string
	Args    []string
	Title   string
	Hint    string
	Confirm string
	Timeout time.Duration
}

type Result struct {
	Spec     Spec
	Stdout   string
	Stderr   string
	Code     int
	Err      string
	Duration time.Duration
}

var allowedPrograms = map[string]bool{
	"systemctl":       true,
	"loginctl":        true,
	"rfkill":          true,
	"nmcli":           true,
	"ufw":             true,
	"nft":             true,
	"ss":              true,
	"pacman":          true,
	"paccache":        true,
	"reflector":       true,
	"modprobe":        true,
	"rmmod":           true,
	"sysctl":          true,
	"systemd-analyze": true,
	"systemd-escape":  true,
	"systemd-inhibit": true,
	"journalctl":      true,
	"fstrim":          true,
	"poweroff":        true,
	"reboot":          true,
	"localectl":       true,
	"timedatectl":     true,
	"hostnamectl":     true,
	"lsmod":           true,
	"dmesg":           true,
	"lspci":           true,
	"lsusb":           true,
	"modinfo":         true,
	"ethtool":         true,
	"uname":           true,

	"deadeye-blacklist":   true,
	"deadeye-unblacklist": true,
}

const (
	maxArgs     = 16
	maxArgLen   = 256
	maxOutBytes = 256 << 10
)

func (s Spec) Validate() error {
	if !allowedPrograms[s.Program] {
		return fmt.Errorf("program %q is not on the allowlist", s.Program)
	}
	if len(s.Args) > maxArgs {
		return fmt.Errorf("too many arguments: %d", len(s.Args))
	}
	for _, a := range s.Args {
		if len(a) > maxArgLen {
			return fmt.Errorf("argument longer than %d bytes", maxArgLen)
		}
		if strings.ContainsRune(a, '\x00') {
			return errors.New("argument contains NUL")
		}

		if strings.ContainsAny(a, "`;$|&<>\\\n\r") {
			return fmt.Errorf("argument %q looks like a shell command — not allowed", a)
		}
	}
	if s.Title == "" {
		return errors.New("the action has no title")
	}
	if s.Timeout <= 0 {
		s.Timeout = 15 * time.Second
	}
	return nil
}

func (s Spec) HasSideEffects() bool {
	return s.Verb != VerbInfo
}

func RunLocal(ctx context.Context, spec Spec) (Result, error) {
	if spec.Verb != VerbInfo {
		return Result{}, errors.New("only read-only commands may run locally")
	}
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	start := time.Now()
	resp := runCommand(spec)
	res := Result{
		Spec:     spec,
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		Code:     resp.Code,
		Duration: time.Since(start),
	}
	if resp.Err != "" {
		res.Err = resp.Err
		return res, errors.New(resp.Err)
	}
	return res, nil
}
