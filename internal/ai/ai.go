package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"deadeye/internal/anomaly"
	"deadeye/internal/human"
	"deadeye/internal/proc"
)

type Config struct {
	Enabled bool `toml:"enabled" json:"enabled"`

	Endpoint string `toml:"endpoint" json:"endpoint"`

	Model string `toml:"model" json:"model"`

	MaxTokens int `toml:"max_tokens" json:"max_tokens"`

	Temperature float64 `toml:"temperature" json:"temperature"`

	TimeoutMs int `toml:"timeout_ms" json:"timeout_ms"`

	KeepAlive string `toml:"keep_alive" json:"keep_alive"`

	SystemPrompt string `toml:"system_prompt" json:"system_prompt"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:     true,
		Endpoint:    "http://127.0.0.1:11434",
		Model:       "qwen2.5:1.5b",
		MaxTokens:   220,
		Temperature: 0.2,
		TimeoutMs:   90000,
		KeepAlive:   "0",
		SystemPrompt: "You are a helper in a Linux process diagnostics program. " +
			"Answer in Russian, briefly (2-4 sentences), without markdown and lists. " +
			"Rely only on the numbers provided. If the data is insufficient, say so. " +
			"Do not invent causes that are not in the digest.",
	}
}

func (c *Config) Validate() error {
	if c.Endpoint == "" {
		c.Endpoint = DefaultConfig().Endpoint
	}
	if !strings.HasPrefix(c.Endpoint, "http://") && !strings.HasPrefix(c.Endpoint, "https://") {
		return fmt.Errorf("ai.endpoint = %q: expected an address like http://127.0.0.1:11434", c.Endpoint)
	}
	c.Endpoint = strings.TrimRight(c.Endpoint, "/")
	if c.Model == "" {
		c.Model = DefaultConfig().Model
	}
	if c.MaxTokens <= 0 {
		c.MaxTokens = DefaultConfig().MaxTokens
	}
	if c.MaxTokens > 4096 {
		return fmt.Errorf("ai.max_tokens = %d: more than 4096 makes no sense for a local model", c.MaxTokens)
	}
	if c.Temperature < 0 || c.Temperature > 2 {
		return fmt.Errorf("ai.temperature = %v: expected between 0 and 2", c.Temperature)
	}
	if c.TimeoutMs < 1000 {
		c.TimeoutMs = DefaultConfig().TimeoutMs
	}
	if c.KeepAlive == "" {
		c.KeepAlive = "0"
	}
	if c.SystemPrompt == "" {
		c.SystemPrompt = DefaultConfig().SystemPrompt
	}
	return nil
}

type Status struct {
	Available bool
	Endpoint  string
	Model     string
	Models    []string
	Err       string
	Hint      string
	CheckedAt time.Time
	LatencyMs int64
}

type Provider interface {
	Generate(ctx context.Context, system, prompt string) (string, error)
	Probe(ctx context.Context) Status
}

type Client struct {
	cfg Config
	hc  *http.Client

	mu   sync.Mutex
	last Status
}

func NewClient(cfg Config) *Client {
	if err := cfg.Validate(); err != nil {

		cfg = DefaultConfig()
	}
	return &Client{
		cfg: cfg,
		hc: &http.Client{
			Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		},
	}
}

func (c *Client) Config() Config { return c.cfg }

func (c *Client) LastStatus() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

type ollamaTags struct {
	Models []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	} `json:"models"`
}

type ollamaRequest struct {
	Model     string            `json:"model"`
	Prompt    string            `json:"prompt"`
	System    string            `json:"system,omitempty"`
	Stream    bool              `json:"stream"`
	KeepAlive string            `json:"keep_alive"`
	Options   map[string]any    `json:"options,omitempty"`
	Raw       bool              `json:"raw,omitempty"`
	Format    string            `json:"format,omitempty"`
	Extra     map[string]string `json:"-"`
}

type ollamaResponse struct {
	Response           string `json:"response"`
	Model              string `json:"model"`
	Done               bool   `json:"done"`
	EvalCount          int    `json:"eval_count"`
	TotalDuration      int64  `json:"total_duration"`
	Error              string `json:"error"`
	ModelNotFoundError string `json:"message"`
}

func (c *Client) Probe(ctx context.Context) Status {
	st := Status{
		Endpoint:  c.cfg.Endpoint,
		Model:     c.cfg.Model,
		CheckedAt: time.Now(),
	}
	start := time.Now()

	if !c.cfg.Enabled {
		st.Err = "model calls are disabled in the config (ai.enabled = false)"
		st.Hint = "set ai.enabled = true in the config"
		c.save(st)
		return st
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Endpoint+"/api/tags", nil)
	if err != nil {
		st.Err = "failed to build the request: " + err.Error()
		c.save(st)
		return st
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		st.Err = "Ollama is not responding: " + shortErr(err)
		st.Hint = "run the server: ollama serve   (and check port 11434 is listening)"
		c.save(st)
		return st
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		st.Err = fmt.Sprintf("Ollama answered with code %d: %s", resp.StatusCode, truncate(string(body), 120))
		c.save(st)
		return st
	}
	var tags ollamaTags
	if err := json.Unmarshal(body, &tags); err != nil {
		st.Err = "unexpected Ollama response: " + shortErr(err)
		c.save(st)
		return st
	}
	for _, m := range tags.Models {
		st.Models = append(st.Models, m.Name)
	}
	sort.Strings(st.Models)
	st.LatencyMs = time.Since(start).Milliseconds()

	switch {
	case len(st.Models) == 0:
		st.Err = "Ollama is running but no models are installed"
		st.Hint = "ollama pull " + c.cfg.Model
	case c.hasModel(st.Models, c.cfg.Model):
		st.Available = true
	default:
		st.Err = "model " + c.cfg.Model + " is not among the installed ones"
		st.Hint = "ollama pull " + c.cfg.Model + "   (or set your own in ai.model)"
	}
	c.save(st)
	return st
}

func (c *Client) hasModel(installed []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	base := strings.SplitN(want, ":", 2)[0]
	for _, name := range installed {
		n := strings.ToLower(name)
		if n == want || n == want+":latest" {
			return true
		}
		if strings.SplitN(n, ":", 2)[0] == base {
			return true
		}
	}
	return false
}

func (c *Client) save(st Status) {
	c.mu.Lock()
	c.last = st
	c.mu.Unlock()
}

func (c *Client) Generate(ctx context.Context, system, prompt string) (string, error) {
	if !c.cfg.Enabled {
		return "", fmt.Errorf("model calls are disabled (ai.enabled = false)")
	}
	body := ollamaRequest{
		Model:     c.cfg.Model,
		Prompt:    prompt,
		System:    system,
		Stream:    false,
		KeepAlive: c.cfg.KeepAlive,
		Options: map[string]any{
			"num_predict":    c.cfg.MaxTokens,
			"temperature":    c.cfg.Temperature,
			"top_p":          0.9,
			"repeat_penalty": 1.1,
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to build the request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint+"/api/generate", bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("failed to build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("Ollama is not responding (%v). Run: ollama serve", shortErr(err))
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read the response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {

		msg := errField(data)
		low := strings.ToLower(msg)
		switch {
		case resp.StatusCode == http.StatusNotFound || strings.Contains(low, "not found"):
			if msg == "" {
				msg = "the server does not know this model"
			}
			return "", fmt.Errorf("model %s not found (%s). Download it: ollama pull %s",
				c.cfg.Model, truncate(msg, 120), c.cfg.Model)
		case strings.Contains(low, "connection refused"):
			return "", fmt.Errorf("Ollama is not responding: %s. Start it: ollama serve", truncate(msg, 120))
		case msg == "":
			return "", fmt.Errorf("Ollama returned code %d: %s", resp.StatusCode, truncate(string(data), 200))
		}
		return "", fmt.Errorf("Ollama returned code %d: %s", resp.StatusCode, truncate(msg, 200))
	}
	var out ollamaResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("failed to parse the response: %w (body: %s)", err, truncate(string(data), 120))
	}
	if out.Error != "" {
		return "", fmt.Errorf("the model reported an error: %s", out.Error)
	}
	if out.ModelNotFoundError != "" && strings.Contains(strings.ToLower(out.ModelNotFoundError), "not found") {
		return "", fmt.Errorf("model %s not found: ollama pull %s", c.cfg.Model, c.cfg.Model)
	}
	text := strings.TrimSpace(out.Response)
	if text == "" {
		return "", fmt.Errorf("the model returned an empty response")
	}
	return text, nil
}

func errField(data []byte) string {
	var out struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &out) != nil {
		return ""
	}
	if out.Error != "" {
		return strings.TrimSpace(out.Error)
	}
	return strings.TrimSpace(out.Message)
}

func shortErr(err error) string { return truncate(err.Error(), 160) }

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + "…"
}

func ProcessDigest(s proc.Snapshot, anoms []anomaly.Anomaly, descendants int, uptime time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Process %s (PID %d, parent %d), owner %s.\n",
		s.DisplayName(), s.PID, s.PPID, orDash(s.User))
	fmt.Fprintf(&b, "Command: %s\n", truncate(orDash(s.Cmdline), 200))
	fmt.Fprintf(&b, "State: %s (%s), threads %d, nice %d, priority %s.\n",
		s.State, s.StateName, s.Threads, s.Nice, schedLabel(s))
	fmt.Fprintf(&b, "Resources: CPU %.1f%%, resident memory %.1f MiB, virtual %.1f MiB, lifetime %s.\n",
		s.CPUPercent, float64(s.RSSKiB)/1024, float64(s.VmSizeKiB)/1024,
		human.Duration(time.Since(s.StartTime)))
	if s.SwapKiB > 0 {
		fmt.Fprintf(&b, "Swapped out: %.1f MiB.\n", float64(s.SwapKiB)/1024)
	}
	if s.FDAccessible {
		fmt.Fprintf(&b, "File fds: %d of %d (%.0f%% of the limit).\n",
			s.FDCount, s.FDLimit, s.FDPercent*100)
	} else {
		b.WriteString("File fds: no permission to read them (root needed).\n")
	}
	if s.ReadBytes > 0 || s.WriteBytes > 0 {
		fmt.Fprintf(&b, "Disk: read %s, written %s.\n",
			human.Bytes(float64(s.ReadBytes)), human.Bytes(float64(s.WriteBytes)))
	}
	if descendants > 0 {
		fmt.Fprintf(&b, "Descendants: %d.\n", descendants)
	}
	if len(anoms) > 0 {
		parts := make([]string, 0, len(anoms))
		for _, a := range anoms {
			parts = append(parts, string(a.Kind)+": "+a.Detail)
		}
		fmt.Fprintf(&b, "Detected anomalies: %s.\n", truncate(strings.Join(parts, "; "), 300))
	} else {
		b.WriteString("No anomalies detected.\n")
	}
	if uptime > 0 {
		fmt.Fprintf(&b, "System uptime: %s.\n", human.Duration(uptime))
	}
	return b.String()
}

func SystemDigest(total, running, blocked, zombies int, cpuPercent, memUsed, memTotal float64,
	top []proc.Snapshot, uptime time.Duration) string {

	var b strings.Builder
	fmt.Fprintf(&b, "System: CPU %.1f%% (load is spread across cores), memory %.1f GiB of %.1f GiB.\n",
		cpuPercent, memUsed/1024/1024, memTotal/1024/1024)
	fmt.Fprintf(&b, "Processes %d: running %d, blocked on I/O %d, zombie %d. Uptime %s.\n",
		total, running, blocked, zombies, human.Duration(uptime))
	if len(top) > 0 {
		b.WriteString("Top consumers:\n")
		for i, s := range top {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&b, "  %d. %s (PID %d, %s): CPU %.1f%%, memory %.1f MiB, state %s.\n",
				i+1, s.DisplayName(), s.PID, orDash(s.User), s.CPUPercent,
				float64(s.RSSKiB)/1024, s.State)
		}
	}
	return b.String()
}

func ExplainProcessPrompt(digest string) string {
	return "Process digest:\n" + digest +
		"\nWhat does this process do, do its metrics look normal, and what is worth checking? " +
		"If the process looks hung or leaks memory, say so directly and suggest one action."
}

func ExplainSystemPrompt(digest string) string {
	return "System summary:\n" + digest +
		"\nAssess the state in two or three sentences and name what needs attention first."
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func schedLabel(s proc.Snapshot) string {
	switch s.Policy {
	case 0:
		return "normal (SCHED_OTHER)"
	case 1:
		return fmt.Sprintf("real-time FIFO, priority %d", s.RTPriority)
	case 2:
		return fmt.Sprintf("real-time round-robin, priority %d", s.RTPriority)
	case 5:
		return "batch (SCHED_BATCH)"
	case 6:
		return "idle (SCHED_IDLE)"
	}
	return fmt.Sprintf("policy %d", s.Policy)
}
