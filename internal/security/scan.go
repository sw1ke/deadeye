package security

import (
	"context"
	"strconv"
	"time"

	"deadeye/internal/proc"
)

func (s *Scanner) Scan(ctx context.Context, procs []proc.Snapshot) Report {
	start := time.Now()
	rep := Report{ProcsSeen: len(procs)}
	if !s.cfg.Enabled {
		rep.Errors = append(rep.Errors,
			"scanner disabled: security.enabled = false")
		rep.ScannedAt = start
		return rep
	}

	rep.Findings = append(rep.Findings, s.Findings(procs)...)

	if s.cfg.ScanAutostart {
		if ctx.Err() != nil {
			rep.Errors = append(rep.Errors, "interrupted before the autostart sweep")
		} else {
			f, items := s.ScanAutostart()
			rep.Findings = append(rep.Findings, f...)
			rep.Autostarts = len(items)
		}
	}
	if s.cfg.ScanNetwork {
		if ctx.Err() != nil {
			rep.Errors = append(rep.Errors, "interrupted before the network scan")
		} else {
			f, listeners := s.ScanNetwork(procs)
			rep.Findings = append(rep.Findings, f...)
			rep.Listeners = len(listeners)
		}
	}

	SortFindings(rep.Findings)
	for _, f := range rep.Findings {
		if f.SHA256 != "" {
			rep.FilesHashed++
		}
	}
	rep.ScannedAt = time.Now()
	rep.Duration = rep.ScannedAt.Sub(start)
	return rep
}

func (s *Scanner) External(ctx context.Context, rep Report,
	onProgress func(done, total int, f Finding)) Report {

	if s.client == nil || !s.client.Available() {
		rep.ExternalDisabled = true
		return rep
	}
	cache := s.cache
	if cache == nil {
		cache = NewHashCache(s.cfg.DeepSeek.CachePath)
		s.cache = cache
	}
	cache.days = s.cfg.DeepSeek.CacheDays

	candidates := make([]int, 0, 8)
	for i, f := range rep.Findings {
		if !f.AskAPI || f.SHA256 == "" {
			continue
		}
		if Level(f.Level) < Level(s.cfg.DeepSeek.MinLevel) {
			continue
		}
		candidates = append(candidates, i)
	}

	for n, idx := range candidates {
		if ctx.Err() != nil {
			rep.Errors = append(rep.Errors, "external check interrupted")
			break
		}
		f := rep.Findings[idx]

		if e, ok := cache.Get(f.SHA256); ok {
			f.Verdict = e.Text() + " (from cache, obtained " +
				e.At.Format("02.01.2006") + ")"
			rep.Findings[idx] = f
			if onProgress != nil {
				onProgress(n+1, len(candidates), f)
			}
			continue
		}

		if cache.BudgetLeft(s.cfg.DeepSeek.MaxRequestsPerDay) <= 0 {
			rep.ExternalSkipped++
			f.Verdict = "external check not run: daily limit exhausted"
			rep.Findings[idx] = f
			if onProgress != nil {
				onProgress(n+1, len(candidates), f)
			}
			continue
		}

		e, err := s.client.Ask(ctx, f)
		rep.ExternalCalls++
		_ = cache.Spend()
		if err != nil {
			f.Verdict = "external check failed: " + err.Error()
		} else {
			f.Verdict = e.Text()
			e.Hash = f.SHA256
			_ = cache.Put(e)
		}
		rep.Findings[idx] = f
		if onProgress != nil {
			onProgress(n+1, len(candidates), f)
		}
	}
	return rep
}

func (s *Scanner) ExternalStatus(rep Report) string {
	if s.client == nil {
		return ""
	}
	if !s.client.Available() {
		return "external check is off: " + s.client.NotAvailableReason()
	}
	left := 0
	if s.cache != nil {
		left = s.cache.BudgetLeft(s.cfg.DeepSeek.MaxRequestsPerDay)
	}
	return "DeepSeek: available today " + strconv.Itoa(left) + " requests of " +
		strconv.Itoa(s.cfg.DeepSeek.MaxRequestsPerDay) + ", in cache " + strconv.Itoa(s.cacheSize()) + " hashes"
}

func (s *Scanner) cacheSize() int {
	if s.cache == nil {
		return 0
	}
	return s.cache.Size()
}
