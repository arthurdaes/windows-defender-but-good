//go:build !windows

package autostart

func IsSupported() bool { return false }
func Enable() error     { return ErrUnsupported }
func Disable() error    { return ErrUnsupported }
func IsEnabled() bool   { return false }
