package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
)

// Sha256File streams a file through SHA-256 without loading it all into memory.
func Sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CachedVerdict is a previously-computed verdict for a hash.
type CachedVerdict struct {
	Verdict      string `json:"verdict"`
	Detections   int    `json:"detections"`
	TotalEngines int    `json:"total_engines"`
}

// Cache is a tiny JSON-backed {sha256: verdict} store, safe for concurrent use.
type Cache struct {
	path string
	mu   sync.Mutex
	data map[string]CachedVerdict
}

func NewCache(path string) *Cache {
	c := &Cache{path: path, data: map[string]CachedVerdict{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c.data)
	}
	return c
}

func (c *Cache) Get(sha string) (CachedVerdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[sha]
	return v, ok
}

func (c *Cache) Put(sha string, v CachedVerdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[sha] = v
	if b, err := json.Marshal(c.data); err == nil {
		_ = os.WriteFile(c.path, b, 0o644)
	}
}

// Blocklist is a concurrency-safe set of known-bad SHA-256 hashes.
type Blocklist struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

func NewBlocklist(hashes []string) *Blocklist {
	b := &Blocklist{set: map[string]struct{}{}}
	b.Add(hashes)
	return b
}

func (b *Blocklist) Add(hashes []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, h := range hashes {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			b.set[h] = struct{}{}
		}
	}
}

func (b *Blocklist) Contains(sha string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.set[strings.ToLower(sha)]
	return ok
}

func (b *Blocklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.set)
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}
