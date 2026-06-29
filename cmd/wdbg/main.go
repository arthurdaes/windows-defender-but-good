// Command wdbg is a lightweight, non-invasive Windows download scanner: it
// watches the Downloads folder and scans new files (blocklist + MalwareBazaar
// feed -> cache -> VirusTotal -> YARA -> heuristics) before you run them,
// warning and reversibly quarantining threats.
package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"wdbg/internal/autostart"
	"wdbg/internal/config"
	"wdbg/internal/feed"
	"wdbg/internal/quarantine"
	"wdbg/internal/scan"
	"wdbg/internal/tray"
	"wdbg/internal/vt"
	"wdbg/internal/watch"
)

type app struct {
	cfg         *config.Config
	scanner     *scan.Scanner
	quar        *quarantine.Quarantine
	watcher     *watch.Watcher
	tray        tray.Tray
	feedStore   *feed.Store
	blocklist   *scan.Blocklist
	stop        chan struct{}
	scanHistory []tray.ScanEntry
	scanHistMu  sync.Mutex
}

func main() {
	setupLogging()
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("could not load config: %v", err)
	}
	a, err := newApp(cfg)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}
	a.run()
}

func setupLogging() {
	log.SetFlags(log.LstdFlags)
	f, err := os.OpenFile(filepath.Join(config.AppDir(), "wdbg.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		log.SetOutput(io.MultiWriter(f, os.Stderr))
	}
}

func newApp(cfg *config.Config) (*app, error) {
	dir := config.AppDir()

	feedStore := &feed.Store{Path: filepath.Join(dir, "blocklist_feed.txt"), Max: cfg.HashFeedMax}
	blocklist := scan.NewBlocklist(feedStore.Load())

	// Local engines: YARA first (signature-grade), then heuristics.
	var engines []scan.LocalEngine
	if re, err := scan.NewRuleEngine(filepath.Join(dir, "rules")); err != nil {
		log.Printf("YARA engine unavailable: %v", err)
	} else {
		engines = append(engines, re)
	}
	engines = append(engines, &scan.Heuristics{Threshold: cfg.HeuristicThreshold})

	// VirusTotal only when a key is set (leave the interface nil otherwise).
	var vtl scan.VTLookup
	if cfg.APIKey != "" {
		vtl = vt.NewClient(cfg.APIKey)
	}

	quar, err := quarantine.New(cfg.QuarantineDir)
	if err != nil {
		return nil, err
	}

	a := &app{
		cfg:       cfg,
		quar:      quar,
		feedStore: feedStore,
		blocklist: blocklist,
		stop:      make(chan struct{}),
		scanner: &scan.Scanner{
			Threshold: cfg.DetectionThreshold,
			VT:        vtl,
			Cache:     scan.NewCache(filepath.Join(dir, "hash_cache.json")),
			Blocklist: blocklist,
			Engines:   engines,
		},
	}
	a.watcher = watch.New(cfg.WatchedFolders, a.onNewDownload, cfg.RiskyOnly)
	a.tray = tray.New(a.handlers())
	return a, nil
}

func (a *app) handlers() tray.Handlers {
	return tray.Handlers{
		ScanPath:         a.onDemandScan,
		OnOpenQuarantine: func() { openPath(a.quar.Dir) },
		OnOpenConfig:     func() { openPath(config.Path()) },
		TogglePause: func() {
			if a.watcher.Paused() {
				a.watcher.Resume()
				a.tray.SetStatus("Resumed — watching for new downloads")
			} else {
				a.watcher.Pause()
				a.tray.SetStatus("Paused")
			}
		},
		IsPaused:           a.watcher.Paused,
		AutostartSupported: autostart.IsSupported(),
		ToggleAutostart: func() {
			var err error
			if autostart.IsEnabled() {
				err = autostart.Disable()
			} else {
				err = autostart.Enable()
			}
			if err != nil {
				a.tray.Notify("Windows Defender but Good", "Could not change startup setting: "+err.Error())
			}
		},
		IsAutostartEnabled: autostart.IsEnabled,
		OnQuit:             a.quit,

		GetConfig: func() *config.Config { return a.cfg },
		SaveConfig: func(c *config.Config) error {
			if err := c.Save(); err != nil {
				return err
			}
			a.cfg = c
			a.scanner.Threshold = c.DetectionThreshold
			if c.APIKey != "" {
				a.scanner.VT = vt.NewClient(c.APIKey)
			} else {
				a.scanner.VT = nil
			}
			return nil
		},
		GetQuarantineList: func() []tray.QuarEntry {
			entries := a.quar.List()
			out := make([]tray.QuarEntry, len(entries))
			for i, e := range entries {
				out[i] = tray.QuarEntry{
					ID:           e.ID,
					OriginalName: e.OriginalName,
					OriginalPath: e.OriginalPath,
					Sha256:       e.Sha256,
					Detail:       e.Detail,
				}
			}
			return out
		},
		RestoreFromQuar: func(id string) error {
			_, err := a.quar.Restore(id)
			return err
		},
		GetScanHistory: func() []tray.ScanEntry {
			a.scanHistMu.Lock()
			defer a.scanHistMu.Unlock()
			out := make([]tray.ScanEntry, len(a.scanHistory))
			copy(out, a.scanHistory)
			return out
		},
		Restart: func() {
			exe, _ := os.Executable()
			_ = exec.Command(exe).Start()
			a.quit()
			a.tray.Stop()
		},
		GetStats: func() tray.AppStats {
			yaraEnabled := false
			for _, eng := range a.scanner.Engines {
				if eng.Name() == "yara" {
					yaraEnabled = true
					break
				}
			}
			return tray.AppStats{
				VTEnabled:       a.cfg.APIKey != "",
				YARAEnabled:     yaraEnabled,
				BlocklistCount:  a.blocklist.Len(),
				CacheCount:      a.scanner.Cache.Len(),
				WatchedFolders:  a.cfg.WatchedFolders,
				HeuristicThresh: a.cfg.HeuristicThreshold,
			}
		},
	}
}

func (a *app) onNewDownload(path string) { a.act(a.scanner.Scan(path), false) }
func (a *app) onDemandScan(path string)  { a.act(a.scanner.Scan(path), true) }

func (a *app) recordScan(r scan.Result) {
	a.scanHistMu.Lock()
	defer a.scanHistMu.Unlock()
	entry := tray.ScanEntry{
		Time:    time.Now().Format("15:04:05"),
		Name:    filepath.Base(r.Path),
		Path:    r.Path,
		Sha256:  r.Sha256,
		Verdict: r.Verdict,
		Engine:  r.Engine,
		Detail:  r.Detail,
	}
	a.scanHistory = append([]tray.ScanEntry{entry}, a.scanHistory...)
	if len(a.scanHistory) > 200 {
		a.scanHistory = a.scanHistory[:200]
	}
}

func (a *app) act(r scan.Result, announceClean bool) {
	a.recordScan(r)
	log.Println(r.Summary())
	switch {
	case r.IsMalicious():
		if _, err := a.quar.Quarantine(r.Path, r.Sha256, r.Summary()); err != nil {
			a.tray.Notify("Windows Defender but Good", "Detected threat but could not quarantine: "+err.Error())
			return
		}
		a.tray.SetStatus("Threat quarantined: " + filepath.Base(r.Path))
		a.tray.Notify("⚠️ Windows Defender but Good threat blocked", r.Summary()+"\nMoved to quarantine.")
	case r.IsSuspicious():
		a.tray.SetStatus("Suspicious file: " + filepath.Base(r.Path))
		a.tray.Notify("⚠️ Windows Defender but Good: suspicious file", r.Summary()+"\nNot quarantined — review before running.")
	case announceClean:
		a.tray.Notify("Windows Defender but Good scan complete", r.Summary())
	default:
		a.tray.SetStatus("Idle — watching for new downloads")
	}
}

func (a *app) run() {
	if err := a.watcher.Start(); err != nil {
		log.Printf("watcher failed to start: %v", err)
	}
	if a.cfg.EnableHashFeed && a.cfg.MalwareBazaarAPIKey != "" {
		go a.feedLoop()
		log.Println("MalwareBazaar hash feed enabled")
	}
	log.Printf("Windows Defender but Good started. Watching: %v", a.cfg.WatchedFolders)
	if err := a.tray.Run(); err != nil {
		log.Printf("tray exited: %v", err)
	}
}

func (a *app) quit() {
	select {
	case <-a.stop:
	default:
		close(a.stop)
	}
	a.watcher.Stop()
}

// feedLoop refreshes the MalwareBazaar feed and updates the live blocklist.
func (a *app) feedLoop() {
	client := feed.NewClient(a.cfg.MalwareBazaarAPIKey)
	for {
		if a.feedStore.IsDue(a.cfg.HashFeedRefreshHours) {
			if hashes, err := client.FetchRecent("100"); err != nil {
				log.Printf("hash feed refresh failed: %v", err)
			} else if added, err := a.feedStore.Merge(hashes); err == nil && added > 0 {
				a.blocklist.Add(a.feedStore.Load())
				log.Printf("hash feed: +%d new (blocklist now %d)", added, a.blocklist.Len())
			}
		}
		wait := time.Duration(a.cfg.HashFeedRefreshHours * float64(time.Hour))
		if wait > time.Hour || wait <= 0 {
			wait = time.Hour
		}
		select {
		case <-a.stop:
			return
		case <-time.After(wait):
		}
	}
}

// openPath opens a file or folder in the OS default handler.
func openPath(p string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", p)
	case "darwin":
		cmd = exec.Command("open", p)
	default:
		cmd = exec.Command("xdg-open", p)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open %s: %v", p, err)
	}
}
