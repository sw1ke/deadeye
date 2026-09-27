package security

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Level int

const (
	LevelNote Level = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelCritical
)

func (l Level) String() string {
	switch l {
	case LevelCritical:
		return "CRITICAL"
	case LevelHigh:
		return "HIGH"
	case LevelMedium:
		return "MEDIUM"
	case LevelLow:
		return "LOW"
	case LevelNote:
		return "NOTE"
	}
	return "?"
}

func (l Level) Mark() string {
	switch l {
	case LevelCritical:
		return "!!!"
	case LevelHigh:
		return "!!"
	case LevelMedium:
		return "!"
	case LevelLow:
		return "+"
	case LevelNote:
		return "·"
	}
	return "?"
}

func (l Level) Weight() int { return int(l) }

type Finding struct {
	Level    Level
	Kind     string
	Subject  string
	PID      int
	Path     string
	Detail   string
	Evidence []string
	Action   string
	SHA256   string
	Size     int64

	AskAPI bool

	Verdict string
}

func (f Finding) Title() string {
	if f.Subject != "" {
		return f.Subject
	}
	return f.Kind
}

type Report struct {
	Findings    []Finding
	ScannedAt   time.Time
	Duration    time.Duration
	ProcsSeen   int
	FilesHashed int
	Autostarts  int
	Listeners   int
	Errors      []string

	ExternalCalls    int
	ExternalSkipped  int
	ExternalDisabled bool
}

func (r Report) ByLevel(min Level) []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Level >= min {
			out = append(out, f)
		}
	}
	return out
}

func (r Report) Counts() map[Level]int {
	out := map[Level]int{}
	for _, f := range r.Findings {
		out[f.Level]++
	}
	return out
}

func (r Report) Worst() Level {
	w := LevelNote
	for _, f := range r.Findings {
		if f.Level > w {
			w = f.Level
		}
	}
	return w
}

func SortFindings(list []Finding) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Level != list[j].Level {
			return list[i].Level > list[j].Level
		}
		if list[i].Kind != list[j].Kind {
			return list[i].Kind < list[j].Kind
		}
		return list[i].Subject < list[j].Subject
	})
}

func (r Report) Summary() string {
	if r.ScannedAt.IsZero() {
		return "no scan has been run yet"
	}
	c := r.Counts()
	if len(r.Findings) == 0 {
		return fmt.Sprintf("checked %d processes, %d autostart entries: no findings",
			r.ProcsSeen, r.Autostarts)
	}
	parts := make([]string, 0, 5)
	for _, l := range []Level{LevelCritical, LevelHigh, LevelMedium, LevelLow, LevelNote} {
		if n := c[l]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", l.Mark(), n))
		}
	}
	return fmt.Sprintf("%d findings (%s) · %s", len(r.Findings), strings.Join(parts, " "),
		r.Worst().String())
}
