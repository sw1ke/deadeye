package ui

import (
	"github.com/charmbracelet/lipgloss"

	"deadeye/internal/proc"
)

var (
	cAccent   = lipgloss.AdaptiveColor{Light: "#4338CA", Dark: "#8B8AFF"}
	cAccent2  = lipgloss.AdaptiveColor{Light: "#0E7490", Dark: "#5EEAD4"}
	cOK       = lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#4ADE80"}
	cWarn     = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}
	cBad      = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"}
	cCritical = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#FF5C5C"}
	cDim      = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#8B8B9E"}
	cText     = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#E5E7EB"}
	cSelBG    = lipgloss.AdaptiveColor{Light: "#DDD6FE", Dark: "#3B3B5C"}
	cBorder   = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#3F3F52"}
	cMagenta  = lipgloss.AdaptiveColor{Light: "#7E22CE", Dark: "#E879F9"}
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	dimStyle   = lipgloss.NewStyle().Foreground(cDim)
	textStyle  = lipgloss.NewStyle().Foreground(cText)
	okStyle    = lipgloss.NewStyle().Foreground(cOK)
	warnStyle  = lipgloss.NewStyle().Foreground(cWarn)
	badStyle   = lipgloss.NewStyle().Foreground(cBad).Bold(true)
	accStyle   = lipgloss.NewStyle().Foreground(cAccent2)

	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(cAccent2)
	colHeadStyle = lipgloss.NewStyle().Bold(true).Foreground(cAccent).Underline(true)

	rowStyle      = lipgloss.NewStyle().Foreground(cText)
	rowDimStyle   = lipgloss.NewStyle().Foreground(cDim)
	rowWarnStyle  = lipgloss.NewStyle().Foreground(cWarn)
	rowBadStyle   = lipgloss.NewStyle().Foreground(cBad)
	rowZombStyle  = lipgloss.NewStyle().Foreground(cMagenta)
	rowOKStyle    = lipgloss.NewStyle().Foreground(cOK)
	selectedStyle = lipgloss.NewStyle().Background(cSelBG).Foreground(cText).Bold(true)

	cShadeBG = lipgloss.AdaptiveColor{Light: "#EDEEF1", Dark: "#1B1B21"}

	groupShadeStyle = lipgloss.NewStyle().Background(cShadeBG)

	cTabBG     = lipgloss.AdaptiveColor{Light: "#E9EAEE", Dark: "#191920"}
	cTabActive = lipgloss.AdaptiveColor{Light: "#1D4ED8", Dark: "#8BE9FD"}

	tabIdleStyle   = lipgloss.NewStyle().Background(cTabBG).Foreground(cDim)
	tabActiveStyle = lipgloss.NewStyle().Background(cTabBG).Foreground(cTabActive).Bold(true).Underline(true)

	boxStyle       = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder).Padding(0, 1)
	boxActiveStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cAccent).Padding(0, 1)
	dialogStyle    = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(cBad).Padding(1, 2)

	keyStyle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)

	catStyle = lipgloss.NewStyle().Foreground(cMagenta)
)

func severityColor(sev float64) lipgloss.TerminalColor {
	switch {
	case sev >= 0.75:
		return cCritical
	case sev >= 0.5:
		return cBad
	case sev >= 0.3:
		return cWarn
	default:
		return cAccent2
	}
}

func cpuColor(pct float64) lipgloss.TerminalColor {
	switch {
	case pct >= 90:
		return cBad
	case pct >= 60:
		return cWarn
	case pct >= 20:
		return cAccent2
	default:
		return cOK
	}
}

func memColor(pct float64) lipgloss.TerminalColor {
	switch {
	case pct >= 90:
		return cBad
	case pct >= 75:
		return cWarn
	case pct >= 40:
		return cAccent2
	default:
		return cOK
	}
}

func stateColor(state string) lipgloss.TerminalColor {
	switch state {
	case proc.StateRunning:
		return cOK
	case proc.StateDiskSleep:
		return cWarn
	case proc.StateZombie:
		return cMagenta
	case proc.StateStopped, proc.StateTraced:
		return cAccent2
	default:
		return cDim
	}
}

func rowStyleFor(s proc.Snapshot, maxSeverity float64, hasAnomaly bool) lipgloss.Style {
	switch {
	case hasAnomaly && maxSeverity >= 0.5:
		return rowBadStyle
	case hasAnomaly:
		return rowWarnStyle
	case s.State == proc.StateZombie:
		return rowZombStyle
	case s.State == proc.StateDiskSleep:
		return rowWarnStyle
	case s.State == proc.StateRunning:
		return rowOKStyle
	default:
		return rowDimStyle
	}
}

var logCursorStyle = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
