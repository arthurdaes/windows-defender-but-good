package scan

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

var riskyExt = map[string]bool{
	".exe": true, ".msi": true, ".scr": true, ".com": true, ".pif": true,
	".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".hta": true,
	".jar": true, ".dll": true, ".sys": true, ".cpl": true, ".lnk": true,
	".zip": true, ".rar": true, ".7z": true, ".iso": true, ".img": true, ".cab": true,
}

var tempExt = map[string]bool{
	".crdownload": true, ".part": true, ".partial": true,
	".download": true, ".tmp": true, ".opdownload": true,
}

// IsTempFile reports whether a file is an incomplete browser download.
func IsTempFile(path string) bool { return tempExt[strings.ToLower(filepath.Ext(path))] }

// IsRisky reports whether a file's extension can carry or execute code.
func IsRisky(path string) bool { return riskyExt[strings.ToLower(filepath.Ext(path))] }

// ReadMOTW reads the Zone.Identifier alternate data stream (Mark-of-the-Web).
// Returns nil when absent or not on NTFS (so it degrades cleanly off Windows).
func ReadMOTW(path string) map[string]string {
	f, err := os.Open(path + ":Zone.Identifier")
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	info := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			info[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if len(info) == 0 {
		return nil
	}
	return info
}

// CameFromInternet is true if the file carries MOTW with an internet zone.
func CameFromInternet(path string) bool {
	m := ReadMOTW(path)
	if m == nil {
		return false
	}
	z := m["ZoneId"]
	return z == "3" || z == "4"
}

// ShouldScan decides whether a completed file is worth scanning.
func ShouldScan(path string, riskyOnly bool) bool {
	if IsTempFile(path) {
		return false
	}
	if !riskyOnly {
		return true
	}
	return IsRisky(path) || CameFromInternet(path)
}
