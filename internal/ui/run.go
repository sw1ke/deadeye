package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/actions"
	"deadeye/internal/anomaly"
	"deadeye/internal/config"
	"deadeye/internal/monitor"
)

func Run(cfg *config.Config, mon *monitor.Monitor, det *anomaly.Detector,
	act *actions.Manager, journal *actions.Log, version string) error {

	updates, unsub := mon.Subscribe()
	defer unsub()

	m := NewModel(cfg, mon, det, act, journal, version, updates)

	opts := []tea.ProgramOption{tea.WithAltScreen()}
	if cfg.UI.FPS > 0 {
		opts = append(opts, tea.WithFPS(cfg.UI.FPS))
	}
	if cfg.UI.MouseSupport {
		opts = append(opts, tea.WithMouseCellMotion())
	}

	p := tea.NewProgram(m, opts...)

	m.SetProgram(p)

	act.SetNotify(func(text string, isErr bool) {
		p.Send(noteMsg{text: text, isErr: isErr})
	})

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("interface exited with error: %w", err)
	}
	return nil
}
