//go:build !yara

package scan

import "errors"

// RuleEngine is a no-op placeholder used when YARA support is not compiled in.
// Build with -tags yara (and CGO_ENABLED=1 + libyara) to get real YARA scanning.
type RuleEngine struct{}

func NewRuleEngine(_ string) (*RuleEngine, error) {
	return nil, errors.New("YARA not compiled into this binary")
}

func (r *RuleEngine) Name() string                     { return "yara" }
func (r *RuleEngine) Scan(_, _ string) (string, string) { return LevelNone, "" }
