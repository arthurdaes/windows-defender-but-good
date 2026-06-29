// Package scan orchestrates the layered scan pipeline and the local engines.
package scan

import (
	"fmt"
	"log"
	"path/filepath"
)

// Verdicts.
const (
	Clean      = "clean"
	Malicious  = "malicious"
	Suspicious = "suspicious"
	Unknown    = "unknown"
	ScanError  = "error"
)

// Local engine levels.
const (
	LevelMalicious  = "malicious"
	LevelSuspicious = "suspicious"
	LevelNone       = "none"
)

// Result is the outcome of scanning one file.
type Result struct {
	Path         string
	Sha256       string
	Verdict      string
	Detections   int
	TotalEngines int
	Engine       string
	Detail       string
}

func (r Result) IsMalicious() bool  { return r.Verdict == Malicious }
func (r Result) IsSuspicious() bool { return r.Verdict == Suspicious }

func (r Result) Summary() string {
	name := filepath.Base(r.Path)
	switch r.Verdict {
	case Malicious:
		if r.Engine == "virustotal" {
			return fmt.Sprintf("⚠️ %s — flagged by %d/%d engines", name, r.Detections, r.TotalEngines)
		}
		return fmt.Sprintf("⚠️ %s — malicious (%s)", name, r.Detail)
	case Suspicious:
		return fmt.Sprintf("⚠️ %s — suspicious (%s)", name, r.Detail)
	case Clean:
		return fmt.Sprintf("%s — clean (%d engines)", name, r.TotalEngines)
	case Unknown:
		return fmt.Sprintf("%s — unknown (not seen by VirusTotal or local engines)", name)
	default:
		return fmt.Sprintf("%s — could not scan: %s", name, r.Detail)
	}
}

// VTLookup looks a hash up against VirusTotal. found=false means VT has never
// seen it (404); err is returned for auth/quota/network failures.
type VTLookup interface {
	Lookup(sha256 string) (found bool, malicious, total int, err error)
}

// LocalEngine is an offline detector consulted when VirusTotal gives no verdict.
type LocalEngine interface {
	Name() string
	// Scan returns a level (LevelMalicious/LevelSuspicious/LevelNone) and detail.
	Scan(path, sha256 string) (level, detail string)
}

// Scanner runs the cheap→expensive pipeline. VirusTotal is primary; local
// engines are consulted only when VT can't decide.
type Scanner struct {
	Threshold int
	VT        VTLookup // may be nil (no API key)
	Cache     *Cache
	Blocklist *Blocklist
	Engines   []LocalEngine
}

func (s *Scanner) Scan(path string) Result {
	sha, err := Sha256File(path)
	if err != nil {
		return Result{Path: path, Verdict: ScanError, Detail: "read error: " + err.Error()}
	}

	// 1. Instant offline blocklist.
	if s.Blocklist != nil && s.Blocklist.Contains(sha) {
		return Result{Path: path, Sha256: sha, Verdict: Malicious,
			Engine: "blocklist", Detail: "matched known-bad hash list"}
	}

	// 2. Cached prior verdict.
	if s.Cache != nil {
		if v, ok := s.Cache.Get(sha); ok {
			return Result{Path: path, Sha256: sha, Verdict: v.Verdict,
				Detections: v.Detections, TotalEngines: v.TotalEngines,
				Engine: "cache", Detail: "cached result"}
		}
	}

	// 3. VirusTotal — the primary verdict source.
	if s.VT != nil {
		found, mal, total, err := s.VT.Lookup(sha)
		if err != nil {
			log.Printf("VirusTotal lookup failed for %s: %v", path, err)
		} else if found {
			verdict := Clean
			if mal >= s.Threshold {
				verdict = Malicious
			}
			if s.Cache != nil {
				s.Cache.Put(sha, CachedVerdict{verdict, mal, total})
			}
			return Result{Path: path, Sha256: sha, Verdict: verdict,
				Detections: mal, TotalEngines: total, Engine: "virustotal"}
		}
		// found==false (404) or error: fall through to local engines.
	}

	// 4. Local engines (YARA first, then heuristics).
	if r, ok := s.runEngines(path, sha); ok {
		if r.Verdict == Malicious && s.Cache != nil {
			s.Cache.Put(sha, CachedVerdict{Verdict: Malicious})
		}
		return r
	}

	detail := "no API key; local engines had no opinion"
	if s.VT != nil {
		detail = "not seen by VirusTotal or local engines"
	}
	return Result{Path: path, Sha256: sha, Verdict: Unknown, Engine: "none", Detail: detail}
}

func (s *Scanner) runEngines(path, sha string) (Result, bool) {
	var suspicious *Result
	for _, e := range s.Engines {
		level, detail := e.Scan(path, sha)
		switch level {
		case LevelMalicious:
			return Result{Path: path, Sha256: sha, Verdict: Malicious,
				Engine: e.Name(), Detail: detail}, true
		case LevelSuspicious:
			if suspicious == nil {
				r := Result{Path: path, Sha256: sha, Verdict: Suspicious,
					Engine: e.Name(), Detail: detail}
				suspicious = &r
			}
		}
	}
	if suspicious != nil {
		return *suspicious, true
	}
	return Result{}, false
}
