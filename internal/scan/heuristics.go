package scan

import (
	"debug/pe"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Heuristics is a static, offline detector. Its signals are lower-confidence
// (legit software is often packed/unsigned), so a hit is reported Suspicious.
type Heuristics struct {
	Threshold int
}

func (h *Heuristics) Name() string { return "heuristics" }

const entropySample = 1 << 20 // 1 MiB

var suspiciousImports = []string{
	"virtualallocex", "writeprocessmemory", "createremotethread",
	"setwindowshookex", "urldownloadtofile", "winexec", "shellexecute",
	"createprocess", "loadlibrary", "getprocaddress", "ntunmapviewofsection",
	"resumethread", "setthreadcontext", "cryptdecrypt", "internetopenurl",
}

var execExt = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".pif": true,
	".bat": true, ".cmd": true, ".js": true, ".vbs": true, ".jar": true,
}
var fakeDocExt = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".jpg": true, ".jpeg": true,
	".png": true, ".txt": true, ".mp4": true, ".xls": true, ".xlsx": true,
}

func (h *Heuristics) Scan(path, sha string) (string, string) {
	score := 0
	var reasons []string

	if doubleExtension(filepath.Base(path)) {
		score += 3
		reasons = append(reasons, "disguised double extension")
	}

	sample, err := readSample(path, entropySample)
	if err != nil {
		return LevelNone, ""
	}
	if shannon(sample) > 7.2 {
		score += 2
		reasons = append(reasons, "high entropy (packed/encrypted)")
	}

	if len(sample) >= 2 && sample[0] == 'M' && sample[1] == 'Z' {
		score += peSignals(path, &reasons)
	}

	if score >= h.Threshold {
		return LevelSuspicious, fmt.Sprintf("heuristic score %d: %s", score, strings.Join(reasons, "; "))
	}
	return LevelNone, ""
}

func doubleExtension(name string) bool {
	parts := strings.Split(strings.ToLower(name), ".")
	if len(parts) < 3 {
		return false
	}
	return execExt["."+parts[len(parts)-1]] && fakeDocExt["."+parts[len(parts)-2]]
}

func readSample(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, err := f.Read(buf)
	if err != nil && read == 0 {
		return nil, err
	}
	return buf[:read], nil
}

func shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// peSignals adds PE-structure based suspicion. Returns the score contribution.
func peSignals(path string, reasons *[]string) int {
	f, err := pe.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	score := 0

	// Suspicious imported API names.
	if syms, err := f.ImportedSymbols(); err == nil {
		var hits []string
		for _, sym := range syms {
			low := strings.ToLower(sym) // form: "Func:DLL"
			for _, want := range suspiciousImports {
				if strings.Contains(low, want) {
					hits = append(hits, want)
				}
			}
		}
		if len(hits) > 0 {
			score += 2
			*reasons = append(*reasons, "suspicious imports ("+strings.Join(uniq(hits), ", ")+")")
		}
	}

	// A writable+executable, high-entropy section is a classic packer tell.
	const memExecute = 0x20000000
	const memWrite = 0x80000000
	for _, sec := range f.Sections {
		if sec.Characteristics&memWrite != 0 && sec.Characteristics&memExecute != 0 {
			if data, err := sec.Data(); err == nil && shannon(data) > 7.0 {
				score += 2
				*reasons = append(*reasons, "packed code section")
				break
			}
		}
	}

	// No embedded signature (security data directory empty). Index 4 = SECURITY.
	if dir, ok := securityDir(f); ok && (dir.VirtualAddress == 0 || dir.Size == 0) {
		score += 1
		*reasons = append(*reasons, "unsigned")
	}
	return score
}

func securityDir(f *pe.File) (pe.DataDirectory, bool) {
	const securityIndex = 4
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return oh.DataDirectory[securityIndex], true
	case *pe.OptionalHeader32:
		return oh.DataDirectory[securityIndex], true
	}
	return pe.DataDirectory{}, false
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
