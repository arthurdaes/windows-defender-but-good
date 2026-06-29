//go:build yara

package scan

import (
	"strings"
	"testing"
)

// Exercises the real go-yara engine against the embedded EICAR rule — fully
// offline, no network or VirusTotal key needed.
func TestYaraMatchesEicar(t *testing.T) {
	eng, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	dir := t.TempDir()
	p := write(t, dir, "eicar.com", []byte(eicar))
	level, detail := eng.Scan(p, "")
	if level != LevelMalicious {
		t.Fatalf("expected malicious, got %q", level)
	}
	if !strings.Contains(detail, "EICAR") {
		t.Fatalf("detail missing rule name: %q", detail)
	}
}

func TestYaraCleanFileNoMatch(t *testing.T) {
	eng, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	dir := t.TempDir()
	p := write(t, dir, "hello.txt", []byte("just some harmless text"))
	if level, _ := eng.Scan(p, ""); level != LevelNone {
		t.Fatalf("expected none, got %q", level)
	}
}
