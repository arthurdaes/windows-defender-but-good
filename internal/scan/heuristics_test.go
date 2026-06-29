package scan

import (
	"bytes"
	"testing"
)

func TestHeuristicsDoubleExtension(t *testing.T) {
	dir := t.TempDir()
	// High-entropy content (all byte values) -> +2; double extension -> +3; >= 5.
	var blob bytes.Buffer
	for i := 0; i < 600; i++ {
		for b := 0; b < 256; b++ {
			blob.WriteByte(byte(b))
		}
	}
	p := write(t, dir, "invoice.pdf.exe", blob.Bytes())
	h := &Heuristics{Threshold: 5}
	level, detail := h.Scan(p, "")
	if level != LevelSuspicious {
		t.Fatalf("expected suspicious, got %q (%s)", level, detail)
	}
}

func TestHeuristicsIgnoresPlainText(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "notes.txt", bytes.Repeat([]byte("the quick brown fox "), 50))
	h := &Heuristics{Threshold: 5}
	if level, _ := h.Scan(p, ""); level != LevelNone {
		t.Fatalf("expected none, got %q", level)
	}
}

func TestDoubleExtensionDetector(t *testing.T) {
	cases := map[string]bool{
		"invoice.pdf.exe": true,
		"photo.jpg.scr":   true,
		"setup.exe":       false,
		"notes.txt":       false,
		"archive.tar.gz":  false,
	}
	for name, want := range cases {
		if got := doubleExtension(name); got != want {
			t.Errorf("doubleExtension(%q) = %v, want %v", name, got, want)
		}
	}
}
