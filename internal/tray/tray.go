// Package tray provides the system-tray UI. The Windows implementation uses
// walk; other platforms get a no-op stub so the program still builds for dev.
package tray

import "wdbg/internal/config"

// Handlers wires tray menu actions back to the application.
type Handlers struct {
	// ScanPath scans a user-chosen file (the tray owns the file picker).
	ScanPath           func(path string)
	OnOpenQuarantine   func()
	OnOpenConfig       func()
	TogglePause        func()
	IsPaused           func() bool
	AutostartSupported bool
	ToggleAutostart    func()
	IsAutostartEnabled func() bool
	OnQuit             func()

	// Dashboard data callbacks.
	GetConfig         func() *config.Config
	SaveConfig        func(*config.Config) error
	GetQuarantineList func() []QuarEntry
	RestoreFromQuar   func(id string) error
	GetScanHistory    func() []ScanEntry
	GetStats          func() AppStats
	Restart           func() // relaunch exe and exit current process
}

// ScanEntry is one record in the in-memory scan history ring buffer.
type ScanEntry struct {
	Time    string // "15:04:05"
	Name    string // base filename
	Path    string
	Sha256  string
	Verdict string
	Engine  string
	Detail  string
}

// QuarEntry mirrors quarantine.Entry without importing that package from tray.
type QuarEntry struct {
	ID           string
	OriginalName string
	OriginalPath string
	Sha256       string
	Detail       string
}

// AppStats is a snapshot of runtime counters shown on the Status tab.
type AppStats struct {
	VTEnabled       bool
	YARAEnabled     bool
	BlocklistCount  int
	CacheCount      int
	WatchedFolders  []string
	HeuristicThresh int
}

// Tray is the platform-agnostic tray controller.
type Tray interface {
	Run() error // blocks on the message loop until quit
	Stop()
	SetStatus(text string)
	Notify(title, msg string)
}
