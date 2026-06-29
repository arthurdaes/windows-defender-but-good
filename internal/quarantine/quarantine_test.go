package quarantine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineRestoreRoundTrip(t *testing.T) {
	work := t.TempDir()
	orig := filepath.Join(work, "evil.exe")
	if err := os.WriteFile(orig, []byte("bad bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	q, err := New(filepath.Join(t.TempDir(), "q"))
	if err != nil {
		t.Fatal(err)
	}

	e, err := q.Quarantine(orig, "abc123def4567890", "test detection")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orig); !os.IsNotExist(err) {
		t.Fatal("original file should have been moved away")
	}
	if _, err := os.Stat(e.QuarantinePath); err != nil {
		t.Fatalf("quarantined file missing: %v", err)
	}
	if len(q.List()) != 1 {
		t.Fatalf("ledger should have 1 entry, got %d", len(q.List()))
	}

	ok, err := q.Restore(e.ID)
	if err != nil || !ok {
		t.Fatalf("restore ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(orig); err != nil {
		t.Fatalf("original should be restored: %v", err)
	}
	if len(q.List()) != 0 {
		t.Fatal("ledger should be empty after restore")
	}
}
