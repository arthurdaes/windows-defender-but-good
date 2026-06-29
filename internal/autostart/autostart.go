// Package autostart manages an opt-in, per-user launch-at-login entry. On
// Windows it uses the HKCU Run key (no admin, no service). Elsewhere it is a
// no-op so the program builds for development.
package autostart

import "errors"

// ErrUnsupported is returned by Enable/Disable on non-Windows platforms.
var ErrUnsupported = errors.New("autostart is only supported on Windows")
