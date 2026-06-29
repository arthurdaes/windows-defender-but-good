// Package quarantine moves flagged files aside reversibly. Files are renamed
// with a .quarantine suffix so they can't be launched, and recorded in a JSON
// ledger so they can be restored. Nothing is ever deleted.
package quarantine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Entry struct {
	ID             string `json:"id"`
	OriginalName   string `json:"original_name"`
	OriginalPath   string `json:"original_path"`
	QuarantinePath string `json:"quarantine_path"`
	Sha256         string `json:"sha256"`
	Detail         string `json:"detail"`
}

type Quarantine struct {
	Dir        string
	ledgerPath string
	mu         sync.Mutex
	entries    []Entry
}

func New(dir string) (*Quarantine, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	q := &Quarantine{Dir: dir, ledgerPath: filepath.Join(dir, "ledger.json")}
	if b, err := os.ReadFile(q.ledgerPath); err == nil {
		_ = json.Unmarshal(b, &q.entries)
	}
	return q, nil
}

func (q *Quarantine) saveLedger() error {
	b, err := json.MarshalIndent(q.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(q.ledgerPath, b, 0o644)
}

func (q *Quarantine) uniqueDest(name string) string {
	dest := filepath.Join(q.Dir, name+".quarantine")
	for i := 1; ; i++ {
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			return dest
		}
		dest = filepath.Join(q.Dir, fmt.Sprintf("%s.%d.quarantine", name, i))
	}
}

// Quarantine moves path into the quarantine dir and records it.
func (q *Quarantine) Quarantine(path, sha, detail string) (Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	name := filepath.Base(path)
	dest := q.uniqueDest(name)
	if err := moveFile(path, dest); err != nil {
		return Entry{}, err
	}
	abs, _ := filepath.Abs(path)
	id := sha
	if len(id) > 12 {
		id = id[:12]
	}
	e := Entry{
		ID: id, OriginalName: name, OriginalPath: abs,
		QuarantinePath: dest, Sha256: sha, Detail: detail,
	}
	q.entries = append(q.entries, e)
	return e, q.saveLedger()
}

func (q *Quarantine) List() []Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Entry, len(q.entries))
	copy(out, q.entries)
	return out
}

// Restore moves a quarantined file back to its original location.
func (q *Quarantine) Restore(id string) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.entries {
		if e.ID == id {
			if err := os.MkdirAll(filepath.Dir(e.OriginalPath), 0o755); err != nil {
				return false, err
			}
			if err := moveFile(e.QuarantinePath, e.OriginalPath); err != nil {
				return false, err
			}
			q.entries = append(q.entries[:i], q.entries[i+1:]...)
			return true, q.saveLedger()
		}
	}
	return false, nil
}

// moveFile renames, falling back to copy+remove across filesystems.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, in, 0o600); err != nil {
		return err
	}
	return os.Remove(src)
}
