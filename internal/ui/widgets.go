package ui

import (
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"deadeye/internal/human"
)

var partialBlocks = []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'}

var graphBlocks = []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

func bar(frac float64, width int, col lipgloss.TerminalColor) string {
	if width <= 0 {
		return ""
	}
	if math.IsNaN(frac) || math.IsInf(frac, 0) {
		frac = 0
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}

	filledF := frac * float64(width)
	full := int(math.Floor(filledF))
	if full > width {
		full = width
	}

	var filled strings.Builder
	filled.WriteString(strings.Repeat("█", full))
	rest := width - full

	if full < width {
		tail := filledF - float64(full)
		idx := int(math.Round(tail * 8))
		if idx > 0 {
			if idx > 8 {
				idx = 8
			}
			filled.WriteRune(partialBlocks[idx])
			rest--
		}
	}

	out := lipgloss.NewStyle().Foreground(col).Render(filled.String())
	if rest > 0 {
		out += dimStyle.Render(strings.Repeat("░", rest))
	}
	return out
}

func sparkline(values []float64, width, height int, maxV float64, col lipgloss.TerminalColor) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	cols := resample(values, width)

	peak := maxV
	if peak <= 0 {
		for _, v := range cols {
			if v > peak {
				peak = v
			}
		}
	}
	if peak <= 0 {
		peak = 1
	}

	lineStyle := lipgloss.NewStyle().Foreground(col)
	lines := make([]string, 0, height)

	for row := 0; row < height; row++ {

		threshold := float64(height - row)
		var b strings.Builder
		for _, v := range cols {
			level := v / peak * float64(height)
			if level < 0 {
				level = 0
			}
			if level > float64(height) {
				level = float64(height)
			}
			switch {
			case level >= threshold:
				b.WriteRune('█')
			case level <= threshold-1:
				b.WriteRune(' ')
			default:
				idx := int(math.Round((level - (threshold - 1)) * 8))
				if idx < 1 {
					idx = 1
				}
				if idx > 8 {
					idx = 8
				}
				b.WriteRune(graphBlocks[idx])
			}
		}
		lines = append(lines, b.String())
	}

	last := len(lines) - 1
	if last >= 0 && strings.TrimSpace(lines[last]) == "" {
		lines[last] = dimStyle.Render(strings.Repeat("─", width))
	} else if last >= 0 {
		lines[last] = lineStyle.Render(lines[last])
	}
	for i := 0; i < last; i++ {
		lines[i] = lineStyle.Render(lines[i])
	}
	return strings.Join(lines, "\n")
}

func resample(values []float64, n int) []float64 {
	if n <= 0 {
		return nil
	}
	out := make([]float64, n)
	if len(values) == 0 {
		return out
	}
	if len(values) == n {
		copy(out, values)
		return out
	}
	if len(values) < n {
		copy(out[n-len(values):], values)
		return out
	}
	for i := 0; i < n; i++ {
		start := len(values) * i / n
		end := len(values) * (i + 1) / n
		if end <= start {
			end = start + 1
		}
		if end > len(values) {
			end = len(values)
		}
		var sum float64
		for _, v := range values[start:end] {
			sum += v
		}
		out[i] = sum / float64(end-start)
	}
	return out
}

func hbarRow(label string, labelWidth int, frac float64, barWidth int, value string, col lipgloss.TerminalColor) string {
	label = human.PadRight(human.Truncate(label, labelWidth), labelWidth)
	if barWidth < 1 {
		barWidth = 1
	}
	return label + " " + bar(frac, barWidth, col) + " " + value
}

func keyValue(label, value string, col lipgloss.TerminalColor) string {
	return dimStyle.Render(label+": ") + lipgloss.NewStyle().Foreground(col).Render(value)
}

func clip(s string, width int) string { return human.Truncate(s, width) }

func panelBoxH(title, content string, totalWidth, totalH int) string {
	innerW := totalWidth - 4
	if innerW < 8 {
		innerW = 8
	}
	bodyH := totalH - 3
	if bodyH < 1 {
		bodyH = 1
	}
	body := clipPad(headerStyle.Render(title), innerW) + "\n" +
		fitHeight(padLines(content, innerW), bodyH, innerW)
	return boxStyle.Width(innerW + 2).Render(body)
}

func fitHeight(s string, height, width int) string {
	if height < 0 {
		height = 0
	}
	lines := strings.Split(s, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	pad := strings.Repeat(" ", width)
	for len(lines) < height {
		lines = append(lines, pad)
	}
	return strings.Join(lines, "\n")
}

// padToHeight makes the block exactly `height` lines tall: excess lines are
// cut from the bottom, missing lines are padded with width-sized spaces.
// Horizontal normalization happens in View via lipgloss MaxWidth.
func padToHeight(s string, height, width int) string {
	if height <= 0 {
		return ""
	}
	s = strings.TrimRight(s, "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	pad := strings.Repeat(" ", width)
	for len(lines) < height {
		lines = append(lines, pad)
	}
	return strings.Join(lines, "\n")
}

func truncateWords(s string, width int) string {
	if width <= 1 {
		return human.Truncate(s, width)
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	cut := human.Truncate(s, width)
	if i := strings.LastIndex(cut, " "); i > width/2 {
		return strings.TrimRight(cut[:i], " ,;·") + "…"
	}
	return cut
}

func trendline(values []float64, width, height int, col lipgloss.TerminalColor) (string, float64, float64) {
	if width <= 0 || height <= 0 || len(values) == 0 {
		return "", 0, 0
	}
	lo, hi := values[0], values[0]
	for _, v := range values {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	span := hi - lo
	if span <= 0 {

		flat := strings.Repeat(" ", width)
		out := make([]string, height)
		for i := range out {
			out[i] = flat
		}
		out[height-1] = dimStyle.Render(strings.Repeat("─", width))
		return strings.Join(out, "\n"), lo, hi
	}
	shifted := make([]float64, len(values))
	for i, v := range values {
		shifted[i] = v - lo
	}
	return sparkline(shifted, width, height, span, col), lo, hi
}
