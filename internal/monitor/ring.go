package monitor

type ring struct {
	data  []float64
	pos   int
	count int
}

func newRing(n int) *ring {
	if n < 2 {
		n = 2
	}
	return &ring{data: make([]float64, n)}
}

func (r *ring) push(v float64) {
	r.data[r.pos] = v
	r.pos = (r.pos + 1) % len(r.data)
	if r.count < len(r.data) {
		r.count++
	}
}

func (r *ring) values() []float64 {
	out := make([]float64, 0, r.count)
	if r.count == 0 {
		return out
	}
	start := (r.pos - r.count + len(r.data)) % len(r.data)
	for i := 0; i < r.count; i++ {
		out = append(out, r.data[(start+i)%len(r.data)])
	}
	return out
}

func (r *ring) last() (float64, bool) {
	if r.count == 0 {
		return 0, false
	}
	idx := (r.pos - 1 + len(r.data)) % len(r.data)
	return r.data[idx], true
}

func (r *ring) size() int { return r.count }
