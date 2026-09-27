package terminal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/creack/pty"
)

type Terminal struct {
	cmd *exec.Cmd
	m   *os.File

	mu     sync.Mutex
	screen screen
	closed bool
}

func New(args []string, cols, rows int) (*Terminal, error) {
	if len(args) == 0 {
		return nil, errors.New("empty shell command")
	}
	cmd := exec.Command(args[0], args[1:]...)

	cmd.Env = append(os.Environ(), "TERM=xterm")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, err
	}
	return &Terminal{
		cmd:    cmd,
		m:      ptmx,
		screen: newScreen(cols, rows),
	}, nil
}

func (t *Terminal) Read(p []byte) (int, error) {
	n, err := t.m.Read(p)
	if n > 0 {

		t.answerQueries(p[:n])
		t.mu.Lock()
		t.screen.write(p[:n])
		t.mu.Unlock()
	}
	if err == io.EOF {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
	}
	return n, err
}

func (t *Terminal) answerQueries(chunk []byte) {
	var reply []byte
	switch {
	case bytes.Contains(chunk, []byte("\x1b[c")) || bytes.Contains(chunk, []byte("\x1b[0c")):
		reply = []byte("\x1b[?1;2c")
	case bytes.Contains(chunk, []byte("\x1b[>q")):
		reply = []byte("\x1b[>|1;40000;0c")
	}
	if len(reply) > 0 {
		go func() { _, _ = t.m.Write(reply) }()
	}
}

func (t *Terminal) Write(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("the shell has exited")
	}
	_, err := t.m.Write(p)
	return err
}

func (t *Terminal) Closed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *Terminal) Resize(cols, rows int) {
	if cols < 2 {
		cols = 2
	}
	if rows < 2 {
		rows = 2
	}
	_ = pty.Setsize(t.m, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	t.mu.Lock()
	t.screen.resize(cols, rows)
	t.mu.Unlock()
}

func (t *Terminal) Lines() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.screen.lines()
}

func (t *Terminal) Close() {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return
	}
	_ = t.m.Close()
	if t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
	_ = t.cmd.Wait()
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}

func ShellArgs() []string {
	for _, sh := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(sh); err == nil {
			return []string{sh, "-i"}
		}
	}
	return []string{"/bin/sh", "-i"}
}

type screen struct {
	cols, rows   int
	cells        [][]rune
	curX, curY   int
	scratch      []byte
	inQuery      bool
	queryStarted bool
}

func newScreen(cols, rows int) screen {
	return screen{cols: cols, rows: rows, cells: makeGrid(cols, rows)}
}

func makeGrid(cols, rows int) [][]rune {
	g := make([][]rune, rows)
	for i := range g {
		g[i] = make([]rune, cols)
	}
	return g
}

func (s *screen) resize(cols, rows int) {
	s.cols, s.rows = cols, rows
	old := s.cells
	s.cells = makeGrid(cols, rows)
	for y := 0; y < rows && y < len(old); y++ {
		n := cols
		if n > len(old[y]) {
			n = len(old[y])
		}
		copy(s.cells[y][:n], old[y][:n])
	}
	if s.curX >= cols {
		s.curX = cols - 1
	}
	if s.curY >= rows {
		s.curY = rows - 1
	}
}

func (s *screen) newline() {
	if s.curY < s.rows-1 {
		s.curY++
	} else {
		copy(s.cells, s.cells[1:])
		s.cells[s.rows-1] = make([]rune, s.cols)
	}
	s.curX = 0
}

func (s *screen) put(r rune) {
	if s.curX >= s.cols {
		s.newline()
	}
	if s.curY < 0 {
		s.curY = 0
	}
	s.cells[s.curY][s.curX] = r
	s.curX++
}

func (s *screen) write(p []byte) {
	buf := append(s.scratch, p...)
	s.scratch = s.scratch[:0]
	i := 0
	for i < len(buf) {
		b := buf[i]
		switch {
		case b == '\n':
			s.newline()
			i++
		case b == '\r':
			s.curX = 0
			i++
		case b == '\b':
			if s.curX > 0 {
				s.curX--
			}
			i++
		case b == '\t':
			for k := 0; k < 4; k++ {
				s.put(' ')
			}
			i++
		case b == 0x1b:

			if s.inQuery && i+1 < len(buf) && buf[i+1] == '\\' {
				s.inQuery = false
				i += 2
				continue
			}
			consumed := s.consumeEscape(buf[i:])
			if consumed == 0 {
				s.scratch = append(s.scratch, buf[i:]...)
				return
			}
			if s.queryStarted {
				s.inQuery = true
				s.queryStarted = false
			}
			i += consumed
		default:
			if s.inQuery {

				i++
				continue
			}
			r, size := utf8.DecodeRune(buf[i:])
			if r == utf8.RuneError && size == 0 {
				s.scratch = append(s.scratch, buf[i:]...)
				return
			}
			if r < 0x20 {
				i++
				continue
			}
			s.put(r)
			i += size
		}
	}
}

func (s *screen) consumeEscape(buf []byte) int {
	if len(buf) < 2 {
		return 0
	}
	switch buf[1] {
	case '[':
		params, end := parseCSI(buf[2:])
		if end < 0 {
			return 0
		}
		final := buf[2+end]
		s.applyCSI(params, final)
		if final == 'u' {
			s.queryStarted = true
		}
		return 2 + end + 1
	case ']':
		for i := 2; i < len(buf); i++ {
			if buf[i] == 0x07 {
				return i + 1
			}
			if buf[i] == 0x1b {
				if i+1 < len(buf) && buf[i+1] == '\\' {
					return i + 2
				}

				return i
			}
		}
		return 0
	default:
		return 2
	}
}

func parseCSI(rest []byte) ([]int, int) {
	i := 0
	for i < len(rest) {
		b := rest[i]
		if b >= 0x30 && b <= 0x3f {
			i++
			continue
		}
		if b >= 0x20 && b <= 0x2f {
			i++
			continue
		}
		if b >= 0x40 && b <= 0x7e {
			params := parseParams(string(rest[:i]))
			return params, i
		}
		return nil, -1
	}
	return nil, -1
}

func parseParams(s string) []int {
	if s == "" {

		return []int{0}
	}
	s = strings.TrimLeft(s, "?<=>")
	if s == "" {
		return []int{1}
	}
	parts := strings.Split(s, ";")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		if p != "" {
			for _, r := range p {
				if r < '0' || r > '9' {
					n = 0
					break
				}
				n = n*10 + int(r-'0')
			}
		}
		out = append(out, n)
	}
	return out
}

func paramAt(p []int, i, def int) int {
	if i < len(p) && p[i] > 0 {
		return p[i]
	}
	return def
}

func (s *screen) applyCSI(p []int, final byte) {
	switch final {
	case 'A':
		s.curY -= paramAt(p, 0, 1)
	case 'B':
		s.curY += paramAt(p, 0, 1)
	case 'C':
		s.curX += paramAt(p, 0, 1)
	case 'D':
		s.curX -= paramAt(p, 0, 1)
	case 'G', '`':
		s.curX = paramAt(p, 0, 1) - 1
	case 'H', 'f':
		s.curY = paramAt(p, 0, 1) - 1
		s.curX = paramAt(p, 1, 1) - 1
	case 'K':
		switch paramAt(p, 0, 0) {
		case 0:
			s.clearRow(s.curY, s.curX, s.cols)
		case 1:
			s.clearRow(s.curY, 0, s.curX+1)
		case 2:
			s.clearRow(s.curY, 0, s.cols)
		}
	case 'J':
		n := paramAt(p, 0, 0)
		if n == 2 || n == 3 {
			for y := range s.cells {
				s.clearRow(y, 0, s.cols)
			}
			s.curX, s.curY = 0, 0
		}
	}
	s.clampCursor()
}

func (s *screen) clearRow(y, from, to int) {
	if y < 0 || y >= s.rows {
		return
	}
	if from < 0 {
		from = 0
	}
	if to > s.cols {
		to = s.cols
	}
	for x := from; x < to; x++ {
		s.cells[y][x] = ' '
	}
}

func (s *screen) clampCursor() {
	if s.curX < 0 {
		s.curX = 0
	}
	if s.curX >= s.cols {
		s.curX = s.cols - 1
	}
	if s.curY < 0 {
		s.curY = 0
	}
	if s.curY >= s.rows {
		s.curY = s.rows - 1
	}
}

func (s *screen) lines() []string {
	last := s.rows - 1
	for last >= 0 && isEmptyRow(s.cells[last]) {
		last--
	}
	out := make([]string, 0, last+1)
	for y := 0; y <= last; y++ {
		out = append(out, strings.TrimRight(string(s.cells[y]), " \x00"))
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

func isEmptyRow(row []rune) bool {
	for _, r := range row {
		if r != 0 && r != ' ' {
			return false
		}
	}
	return true
}
