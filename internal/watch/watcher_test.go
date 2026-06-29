package watch

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A slow download (file grows, then stops) must trigger exactly one scan, after
// it stabilizes — mirroring the Python wait-for-complete test.
func TestWaitUntilStableFiresOnce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "download.exe")
	if err := os.WriteFile(target, []byte("start"), 0o644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var scanned []string
	w := New([]string{dir}, func(p string) {
		mu.Lock()
		scanned = append(scanned, p)
		mu.Unlock()
	}, false)
	w.stableChecks = 2
	w.pollInterval = 20 * time.Millisecond

	done := make(chan struct{})
	go func() {
		for i := 0; i < 4; i++ {
			f, _ := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0o644)
			f.Write([]byte("xxxx"))
			f.Close()
			time.Sleep(20 * time.Millisecond)
		}
		close(done)
	}()

	w.handle(target)
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(scanned) != 1 {
		t.Fatalf("expected exactly 1 scan, got %d", len(scanned))
	}
}

func TestTempFileSkipped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "movie.mp4.crdownload")
	os.WriteFile(p, []byte("x"), 0o644)
	called := false
	w := New([]string{dir}, func(string) { called = true }, false)
	w.handle(p)
	if called {
		t.Fatal("an incomplete (.crdownload) file should be skipped")
	}
}
