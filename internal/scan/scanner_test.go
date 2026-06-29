package scan

import (
	"os"
	"path/filepath"
	"testing"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

type stubVT struct {
	found      bool
	mal, total int
	err        error
}

func (s stubVT) Lookup(string) (bool, int, int, error) { return s.found, s.mal, s.total, s.err }

type stubEngine struct{ name, level, detail string }

func (e stubEngine) Name() string                   { return e.name }
func (e stubEngine) Scan(string, string) (string, string) { return e.level, e.detail }

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func newCache(t *testing.T) *Cache { return NewCache(filepath.Join(t.TempDir(), "c.json")) }

func TestBlocklistHit(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "bad.bin", []byte("known bad bytes"))
	sha, _ := Sha256File(p)
	s := &Scanner{Threshold: 3, Cache: newCache(t), Blocklist: NewBlocklist([]string{sha})}
	r := s.Scan(p)
	if r.Verdict != Malicious || r.Engine != "blocklist" {
		t.Fatalf("got %+v", r)
	}
}

func TestBelowThresholdClean(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "thing.exe", []byte("not actually a virus"))
	s := &Scanner{Threshold: 3, VT: stubVT{found: true, mal: 1, total: 70}, Cache: newCache(t)}
	if r := s.Scan(p); r.Verdict != Clean {
		t.Fatalf("expected clean, got %+v", r)
	}
}

func TestVTCleanNotOverriddenByLocal(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "sample.com", []byte("harmless test bytes"))
	s := &Scanner{
		Threshold: 3,
		VT:        stubVT{found: true, mal: 0, total: 70},
		Cache:     newCache(t),
		Engines:   []LocalEngine{stubEngine{"stub", LevelMalicious, "would flag"}},
	}
	r := s.Scan(p)
	if r.Verdict != Clean || r.Engine != "virustotal" {
		t.Fatalf("VT-primary violated: %+v", r)
	}
}

func TestLocalCatchesWhenVTUnknown(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "new.exe", []byte("never seen"))
	s := &Scanner{
		Threshold: 3,
		VT:        stubVT{found: false}, // 404 -> local engines decide
		Cache:     newCache(t),
		Engines:   []LocalEngine{stubEngine{"yara", LevelMalicious, "match"}},
	}
	if r := s.Scan(p); r.Verdict != Malicious || r.Engine != "yara" {
		t.Fatalf("got %+v", r)
	}
}

func TestSuspiciousWhenVTUnknown(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "packed.exe", []byte("x"))
	s := &Scanner{
		Threshold: 3,
		VT:        stubVT{found: false},
		Cache:     newCache(t),
		Engines:   []LocalEngine{stubEngine{"heuristics", LevelSuspicious, "score 5"}},
	}
	if r := s.Scan(p); r.Verdict != Suspicious {
		t.Fatalf("expected suspicious, got %+v", r)
	}
}

func TestCacheShortCircuits(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "sample.com", []byte("harmless test bytes"))
	cache := newCache(t)
	s := &Scanner{Threshold: 3, VT: stubVT{found: true, mal: 62, total: 70}, Cache: cache}
	if r := s.Scan(p); r.Verdict != Malicious {
		t.Fatalf("first scan: %+v", r)
	}
	s.VT = nil // ensure no further VT call is possible
	r := s.Scan(p)
	if r.Verdict != Malicious || r.Engine != "cache" {
		t.Fatalf("expected cached malicious, got %+v", r)
	}
}
