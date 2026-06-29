//go:build !windows

package tray

import "log"

type stub struct{}

// New returns a no-op tray (used for development on non-Windows platforms).
func New(Handlers) Tray { return &stub{} }

func (s *stub) Run() error {
	log.Println("tray: system tray is only implemented on Windows; running headless")
	select {} // block like the real message loop would
}
func (s *stub) Stop()                  {}
func (s *stub) SetStatus(string)       {}
func (s *stub) Notify(title, m string) { log.Printf("NOTIFY %s: %s", title, m) }
