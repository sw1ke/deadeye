package human

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB
	TiB = 1024 * GiB
)

func Bytes(b float64) string {
	switch {
	case math.IsNaN(b) || math.IsInf(b, 0):
		return "—"
	case b < 0:
		return "-" + Bytes(-b)
	case b < KiB:
		return fmt.Sprintf("%.0f B", b)
	case b < MiB:
		return trimFloat(b/KiB) + " KiB"
	case b < GiB:
		return trimFloat(b/MiB) + " MiB"
	case b < TiB:
		return trimFloat(b/GiB) + " GiB"
	default:
		return trimFloat(b/TiB) + " TiB"
	}
}

func FromKiB(kib float64) string { return Bytes(kib * KiB) }

func SignedKiB(kib float64) string {
	if math.IsNaN(kib) {
		return "—"
	}
	sign := ""
	if kib > 0 {
		sign = "+"
	} else if kib < 0 {
		sign = "-"
		kib = -kib
	}
	if kib == 0 {
		return "0"
	}
	return sign + FromKiB(kib)
}

func Rate(bytesPerSec float64) string {
	if math.IsNaN(bytesPerSec) || math.IsInf(bytesPerSec, 0) {
		return "—"
	}
	if bytesPerSec <= 0 {
		return "0"
	}
	return Bytes(bytesPerSec) + "/s"
}

func Duration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%ds", int64(d.Seconds()))
	case d < time.Hour:
		m := int64(d.Minutes())
		s := int64(d.Seconds()) - m*60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	case d < 24*time.Hour:
		h := int64(d.Hours())
		m := int64(d.Minutes()) - h*60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		days := int64(d.Hours() / 24)
		h := int64(d.Hours()) - days*24
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd %dh", days, h)
	}
}

func Percent(p float64) string {
	if math.IsNaN(p) || math.IsInf(p, 0) {
		return "—"
	}
	if p > 999 {
		return fmt.Sprintf("%.0f%%", p)
	}
	return fmt.Sprintf("%.1f%%", p)
}

func Count(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		s = strconv.Itoa(-n)
	}
	if len(s) <= 3 {
		return strconv.Itoa(n)
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	out := strings.Join(parts, " ")
	if n < 0 {
		return "-" + out
	}
	return out
}

func Truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string(r[:width-1]) + "…"
}

func Compact(n int64) string {
	switch {
	case n < 0:
		return "-" + Compact(-n)
	case n >= 1_000_000_000_000:
		return fmt.Sprintf("%.1fT", float64(n)/1e12)
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fG", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 100_000:
		return fmt.Sprintf("%.0fk", float64(n)/1e3)
	default:
		return strconv.FormatInt(n, 10)
	}
}

func Plural(n int, one, few, many string) string {
	if n < 0 {
		n = -n
	}
	n10 := n % 10
	n100 := n % 100
	switch {
	case n10 == 1 && n100 != 11:
		return one
	case n10 >= 2 && n10 <= 4 && (n100 < 12 || n100 > 14):
		return few
	}
	return many
}

func Pluralf(n int, one, few, many string) string {
	return strconv.Itoa(n) + " " + Plural(n, one, few, many)
}

func TruncateMiddle(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width <= 3 {
		return Truncate(s, width)
	}
	head := (width - 1) / 2
	tail := width - 1 - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
}

func PadRight(s string, width int) string {
	r := []rune(s)
	if len(r) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(r))
}

func PadLeft(s string, width int) string {
	r := []rune(s)
	if len(r) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(r)) + s
}

func trimFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return s
}
