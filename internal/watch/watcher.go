// Package watch monitors download folders and feeds completed files to a scan
// callback. It waits for in-progress downloads to finish before scanning so the
// hash is computed on the final bytes.
package watch

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"wdbg/internal/scan"
)

type ScanFunc func(path string)

type Watcher struct {
	folders      []string
	onScan       ScanFunc
	riskyOnly    bool
	stableChecks int
	pollInterval time.Duration

	fsw    *fsnotify.Watcher
	queue  chan string
	seen   map[string]struct{}
	seenMu sync.Mutex
	paused atomic.Bool
	stop   chan struct{}
}

func New(folders []string, onScan ScanFunc, riskyOnly bool) *Watcher {
	var existing []string
	for _, f := range folders {
		if fi, err := os.Stat(f); err == nil && fi.IsDir() {
			existing = append(existing, f)
		}
	}
	return &Watcher{
		folders:      existing,
		onScan:       onScan,
		riskyOnly:    riskyOnly,
		stableChecks: 3,
		pollInterval: time.Second,
		queue:        make(chan string, 256),
		seen:         map[string]struct{}{},
		stop:         make(chan struct{}),
	}
}

func (w *Watcher) Start() error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	w.fsw = fsw
	for _, f := range w.folders {
		if err := fsw.Add(f); err != nil {
			log.Printf("watch: cannot watch %s: %v", f, err)
			continue
		}
		log.Printf("Watching %s", f)
	}
	go w.eventLoop()
	go w.processLoop()
	return nil
}

func (w *Watcher) Stop() {
	close(w.stop)
	if w.fsw != nil {
		_ = w.fsw.Close()
	}
}

func (w *Watcher) Pause()       { w.paused.Store(true) }
func (w *Watcher) Resume()      { w.paused.Store(false) }
func (w *Watcher) Paused() bool { return w.paused.Load() }

func (w *Watcher) eventLoop() {
	for {
		select {
		case <-w.stop:
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			// New file appears here on creation and on the .crdownload->final rename.
			if ev.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				select {
				case w.queue <- ev.Name:
				default: // queue full; drop (the file will usually re-trigger)
				}
			}
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			log.Printf("watch: %v", err)
		}
	}
}

func (w *Watcher) processLoop() {
	for {
		select {
		case <-w.stop:
			return
		case path := <-w.queue:
			if w.paused.Load() {
				continue
			}
			w.handle(path)
		}
	}
}

func (w *Watcher) handle(path string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("watch: recovered from panic handling %s: %v", path, r)
		}
	}()

	if scan.IsTempFile(path) {
		return // incomplete download; the final rename re-enqueues it
	}
	if !w.waitUntilStable(path) {
		return
	}
	if !scan.ShouldScan(path, w.riskyOnly) {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	abs, _ := filepath.Abs(path)
	key := abs + "::" + fi.ModTime().String()
	w.seenMu.Lock()
	if _, dup := w.seen[key]; dup {
		w.seenMu.Unlock()
		return
	}
	w.seen[key] = struct{}{}
	w.seenMu.Unlock()

	log.Printf("Scanning new download: %s", path)
	w.onScan(path)
}

// waitUntilStable returns true once the file's size is unchanged across
// stableChecks consecutive polls (i.e. the download finished).
func (w *Watcher) waitUntilStable(path string) bool {
	deadline := time.Now().Add(2 * time.Minute)
	lastSize := int64(-1)
	stable := 0
	for time.Now().Before(deadline) {
		select {
		case <-w.stop:
			return false
		default:
		}
		fi, err := os.Stat(path)
		if err != nil {
			return false
		}
		if fi.Size() == lastSize {
			if stable++; stable >= w.stableChecks {
				return true
			}
		} else {
			stable = 0
			lastSize = fi.Size()
		}
		time.Sleep(w.pollInterval)
	}
	return false
}
