package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"deadeye/internal/human"
)

type DeepSeekConfig struct {
	Enabled   bool   `toml:"enabled" json:"enabled"`
	APIKey    string `toml:"api_key" json:"api_key"`
	Endpoint  string `toml:"endpoint" json:"endpoint"`
	Model     string `toml:"model" json:"model"`
	MaxTokens int    `toml:"max_tokens" json:"max_tokens"`

	Temperature float64 `toml:"temperature" json:"temperature"`
	TimeoutMs   int     `toml:"timeout_ms" json:"timeout_ms"`

	MaxRequestsPerDay int `toml:"max_requests_per_day" json:"max_requests_per_day"`

	MinLevel  int    `toml:"min_level" json:"min_level"`
	CachePath string `toml:"cache_path" json:"cache_path"`
	CacheDays int    `toml:"cache_days" json:"cache_days"`
}

func DefaultDeepSeekConfig() DeepSeekConfig {
	return DeepSeekConfig{
		Enabled:           false,
		Endpoint:          "https://api.deepseek.com",
		Model:             "deepseek-chat",
		MaxTokens:         260,
		Temperature:       0,
		TimeoutMs:         45000,
		MaxRequestsPerDay: 20,
		MinLevel:          int(LevelMedium),
		CachePath:         "",
		CacheDays:         30,
	}
}

func (c *DeepSeekConfig) Validate() error {
	if c.Endpoint == "" {
		c.Endpoint = DefaultDeepSeekConfig().Endpoint
	}
	c.Endpoint = strings.TrimSuffix(c.Endpoint, "/")
	if !strings.HasPrefix(c.Endpoint, "http://") && !strings.HasPrefix(c.Endpoint, "https://") {
		return fmt.Errorf("security.deepseek.endpoint = %q: expected http:// or https://", c.Endpoint)
	}
	if c.Model == "" {
		c.Model = "deepseek-chat"
	}
	if c.MaxTokens <= 0 {
		c.MaxTokens = 260
	}
	if c.MaxTokens > 1000 {
		return fmt.Errorf("security.deepseek.max_tokens = %d: an answer over 1000 tokens is useless here and costs money",
			c.MaxTokens)
	}
	if c.Temperature < 0 || c.Temperature > 1 {
		c.Temperature = 0
	}
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = 45000
	}
	if c.MaxRequestsPerDay <= 0 {
		c.MaxRequestsPerDay = 0
	}
	if c.CacheDays <= 0 {
		c.CacheDays = 30
	}
	if c.CachePath == "" {
		c.CachePath = defaultCachePath()
	}
	return nil
}

func defaultCachePath() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "deadeye", "hashes.json")
	}
	return filepath.Join(os.TempDir(), "deadeye-hashes.json")
}

type CacheEntry struct {
	Hash        string    `json:"hash"`
	Risk        string    `json:"risk"`
	Malicious   string    `json:"malicious"`
	Family      string    `json:"family"`
	Explanation string    `json:"explanation"`
	At          time.Time `json:"at"`
	FromCache   bool      `json:"-"`
}

func (e CacheEntry) Text() string {
	parts := make([]string, 0, 3)
	if e.Risk != "" {
		parts = append(parts, "risk: "+e.Risk)
	}
	if e.Malicious != "" {
		parts = append(parts, "maliciousness: "+e.Malicious)
	}
	if e.Family != "" && e.Family != "-" {
		parts = append(parts, "family: "+e.Family)
	}
	s := strings.Join(parts, ", ")
	if e.Explanation != "" {
		if s != "" {
			s += " — "
		}
		s += e.Explanation
	}
	if s == "" {
		return "empty answer"
	}
	return s
}

type HashCache struct {
	path  string
	mu    sync.Mutex
	items map[string]CacheEntry
	day   string
	used  int
	days  int
}

func NewHashCache(path string) *HashCache {
	c := &HashCache{path: path, items: map[string]CacheEntry{}, days: 30}
	c.load()
	return c
}

type cacheFile struct {
	Items map[string]CacheEntry `json:"items"`
	Day   string                `json:"day"`
	Used  int                   `json:"used"`
}

func (c *HashCache) load() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var f cacheFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.Items != nil {
		c.items = f.Items
	}
	c.day, c.used = f.Day, f.Used
}

func (c *HashCache) save() error {
	c.mu.Lock()
	data, err := json.MarshalIndent(cacheFile{Items: c.items, Day: c.day, Used: c.used}, "", "  ")
	path := c.path
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func today() string { return time.Now().UTC().Format("2006-01-02") }

func (c *HashCache) BudgetLeft(limit int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.day != today() {
		return limit
	}
	left := limit - c.used
	if left < 0 {
		return 0
	}
	return left
}

func (c *HashCache) UsedToday() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.day != today() {
		return 0
	}
	return c.used
}

func (c *HashCache) Spend() error {
	c.mu.Lock()
	if c.day != today() {
		c.day, c.used = today(), 0
	}
	c.used++
	c.mu.Unlock()
	return c.save()
}

func (c *HashCache) Get(hash string) (CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[strings.ToLower(hash)]
	if !ok {
		return CacheEntry{}, false
	}
	if c.days > 0 && time.Since(e.At) > time.Duration(c.days)*24*time.Hour {
		return CacheEntry{}, false
	}
	e.FromCache = true
	return e, true
}

func (c *HashCache) Put(e CacheEntry) error {
	c.mu.Lock()
	if e.At.IsZero() {
		e.At = time.Now()
	}
	c.items[strings.ToLower(e.Hash)] = e
	c.mu.Unlock()
	return c.save()
}

func (c *HashCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

type DeepSeekClient struct {
	cfg DeepSeekConfig
	hc  *http.Client
}

func NewDeepSeekClient(cfg DeepSeekConfig) *DeepSeekClient {
	cfg.Validate()
	return &DeepSeekClient{
		cfg: cfg,
		hc:  &http.Client{Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond},
	}
}

func (c *DeepSeekClient) Available() bool {
	return c.cfg.Enabled && c.cfg.APIKey != "" && c.cfg.MaxRequestsPerDay > 0
}

func (c *DeepSeekClient) Config() DeepSeekConfig { return c.cfg }

func (c *DeepSeekClient) NotAvailableReason() string {
	switch {
	case !c.cfg.Enabled:
		return "external check is off: security.deepseek.enabled = false"
	case c.cfg.APIKey == "":
		return "no key set: security.deepseek.api_key"
	case c.cfg.MaxRequestsPerDay <= 0:
		return "daily limit is zero: external requests are disabled"
	}
	return ""
}

const deepseekSystem = `You analyze signs of malware on Linux.
Given: the SHA-256 of the file, its path, size and local evidence.
Answer strictly in four lines and nothing else:
RISK: low|medium|high|critical
HARM: yes|no|unknown
FAMILY: short name or -
EXPLANATION: one sentence in English.
If no conclusion can be drawn from the hash and evidence, say so. Do not make things up.`

func (c *DeepSeekClient) Ask(ctx context.Context, f Finding) (CacheEntry, error) {
	if !c.Available() {
		return CacheEntry{}, fmt.Errorf("external check unavailable: %s", c.NotAvailableReason())
	}
	prompt := buildDeepseekPrompt(f)
	body, _ := json.Marshal(map[string]any{
		"model":       c.cfg.Model,
		"max_tokens":  c.cfg.MaxTokens,
		"temperature": c.cfg.Temperature,
		"stream":      false,
		"messages": []map[string]string{
			{"role": "system", "content": deepseekSystem},
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.Endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return CacheEntry{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.hc.Do(req)
	if err != nil {
		return CacheEntry{}, fmt.Errorf("request to DeepSeek failed: %w", shortErrDS(err))
	}
	defer resp.Body.Close()

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return CacheEntry{}, fmt.Errorf("DeepSeek response could not be parsed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := "server returned " + strconv.Itoa(resp.StatusCode)
		if out.Error != nil && out.Error.Message != "" {
			msg = out.Error.Message
		}
		if resp.StatusCode == http.StatusUnauthorized {
			msg += " (key rejected)"
		}
		return CacheEntry{}, fmt.Errorf("%s", msg)
	}
	if len(out.Choices) == 0 {
		return CacheEntry{}, fmt.Errorf("empty response: the model returned no choices")
	}
	e := parseVerdict(out.Choices[0].Message.Content)
	e.Hash = f.SHA256
	e.At = time.Now()
	return e, nil
}

func buildDeepseekPrompt(f Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SHA256: %s\nPath: %s\nSize: %s\nIndicator: %s\nDetail: %s\n",
		f.SHA256, orDash(f.Path), human.Bytes(float64(f.Size)), f.Kind, f.Detail)
	for i, ev := range f.Evidence {
		if i >= 4 {
			break
		}
		fmt.Fprintf(&b, "Evidence: %s\n", human.TruncateMiddle(ev, 160))
	}
	return b.String()
}

func parseVerdict(text string) CacheEntry {
	e := CacheEntry{Explanation: strings.TrimSpace(text)}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		up := strings.ToUpper(ln)
		val := ""
		switch {
		case strings.HasPrefix(up, "RISK:"):
			val = strings.TrimSpace(ln[len("RISK:"):])
			e.Risk = val
		case strings.HasPrefix(up, "HARM:"):
			val = strings.TrimSpace(ln[len("HARM:"):])
			e.Malicious = val
		case strings.HasPrefix(up, "FAMILY:"):
			val = strings.TrimSpace(ln[len("FAMILY:"):])
			e.Family = val
		case strings.HasPrefix(up, "EXPLANATION:"):
			val = strings.TrimSpace(ln[len("EXPLANATION:"):])
			e.Explanation = val
		default:
			continue
		}
		if e.Risk != "" || e.Malicious != "" || e.Family != "" {

			if e.Explanation == strings.TrimSpace(text) {
				e.Explanation = ""
			}
		}
	}
	if e.Explanation == "" && e.Risk == "" {
		e.Explanation = strings.TrimSpace(text)
	}
	return e
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shortErrDS(err error) error {
	s := err.Error()
	if len(s) > 220 {
		return fmt.Errorf("%s…", s[:220])
	}
	return err
}
