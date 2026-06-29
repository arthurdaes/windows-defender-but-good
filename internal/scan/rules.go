//go:build yara

package scan

import (
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	yara "github.com/hillu/go-yara/v4"
)

//go:embed rules/*.yar
var bundledRules embed.FS

// RuleEngine matches files against compiled YARA rules. A match is treated as
// signature-grade -> Malicious.
type RuleEngine struct {
	rules *yara.Rules
}

// NewRuleEngine compiles the embedded starter rules plus any *.yar/*.yara in
// userRulesDir (which may be empty/absent).
func NewRuleEngine(userRulesDir string) (*RuleEngine, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}

	entries, err := bundledRules.ReadDir("rules")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yar") {
			continue
		}
		data, err := bundledRules.ReadFile("rules/" + e.Name())
		if err != nil {
			return nil, err
		}
		if err := c.AddString(string(data), e.Name()); err != nil {
			return nil, fmt.Errorf("compiling bundled rule %s: %w", e.Name(), err)
		}
	}

	if userRulesDir != "" {
		if des, err := os.ReadDir(userRulesDir); err == nil {
			for _, de := range des {
				n := de.Name()
				if !strings.HasSuffix(n, ".yar") && !strings.HasSuffix(n, ".yara") {
					continue
				}
				b, err := os.ReadFile(filepath.Join(userRulesDir, n))
				if err != nil {
					continue
				}
				if err := c.AddString(string(b), n); err != nil {
					// Skip a bad user ruleset rather than failing startup.
					log.Printf("YARA: skipping user rule %s: %v", n, err)
				}
			}
		}
	}

	rules, err := c.GetRules()
	if err != nil {
		return nil, err
	}
	return &RuleEngine{rules: rules}, nil
}

func (r *RuleEngine) Name() string { return "yara" }

func (r *RuleEngine) Scan(path, sha string) (string, string) {
	var matches yara.MatchRules
	if err := r.rules.ScanFile(path, 0, 0, &matches); err != nil {
		log.Printf("YARA: scan failed for %s: %v", path, err)
		return LevelNone, ""
	}
	if len(matches) == 0 {
		return LevelNone, ""
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.Rule
	}
	return LevelMalicious, "YARA rule match: " + strings.Join(names, ", ")
}
