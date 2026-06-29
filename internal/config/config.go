// Package config loads and persists Windows Defender but Good's settings and resolves its on-disk
// paths (%APPDATA%\Windows Defender but Good on Windows; ~/.config/Windows Defender but Good elsewhere for dev).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

const AppName = "Windows Defender but Good"

// Config mirrors the settings of the original Python implementation.
type Config struct {
	APIKey               string   `json:"api_key"`
	WatchedFolders       []string `json:"watched_folders"`
	DetectionThreshold   int      `json:"detection_threshold"`
	RiskyOnly            bool     `json:"risky_only"`
	HeuristicThreshold   int      `json:"heuristic_threshold"`
	EnableHashFeed       bool     `json:"enable_hash_feed"`
	MalwareBazaarAPIKey  string   `json:"malwarebazaar_api_key"`
	HashFeedRefreshHours float64  `json:"hash_feed_refresh_hours"`
	HashFeedMax          int      `json:"hash_feed_max"`
	QuarantineDir        string   `json:"quarantine_dir"`
}

// AppDir returns the per-user data directory, creating it if needed.
func AppDir() string {
	var base string
	if runtime.GOOS == "windows" {
		if base = os.Getenv("APPDATA"); base == "" {
			base, _ = os.UserHomeDir()
		}
	} else {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	d := filepath.Join(base, AppName)
	_ = os.MkdirAll(d, 0o755)
	return d
}

// DefaultDownloads is the user's Downloads folder.
func DefaultDownloads() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads")
}

// Path is the location of config.json.
func Path() string { return filepath.Join(AppDir(), "config.json") }

// Default returns a Config populated with safe defaults.
func Default() *Config {
	return &Config{
		WatchedFolders:       []string{DefaultDownloads()},
		DetectionThreshold:   3,
		HeuristicThreshold:   5,
		EnableHashFeed:       true,
		HashFeedRefreshHours: 12,
		HashFeedMax:          50000,
		QuarantineDir:        filepath.Join(AppDir(), "quarantine"),
	}
}

// Load reads config.json, creating it with defaults if absent. Unmarshalling
// onto a defaults-populated struct means missing keys keep their defaults.
func Load() (*Config, error) {
	data, err := os.ReadFile(Path())
	if os.IsNotExist(err) {
		c := Default()
		return c, c.Save()
	}
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Save writes the config as indented JSON.
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(Path(), data, 0o644)
}
