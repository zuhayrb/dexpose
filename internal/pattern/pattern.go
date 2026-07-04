// Package pattern loads a gitleaks-compatible rules.toml file, compiles each
// rule's regex at startup, and matches strings against the compiled set.
//
// The package is intentionally narrow: it knows nothing about APKs, output
// formats, or ignore logic. Its only job is "given a string, which rules fire?"
package pattern

import (
	"fmt"
	"regexp"

	"github.com/BurntSushi/toml"
)

// Rule is a single entry from a rules.toml file.
// Only the fields dexpose needs are decoded; additional gitleaks fields present
// in the TOML (allowlist, tags, entropy, etc.) are silently ignored.
type Rule struct {
	// ID is the unique name for this rule, e.g. "stripe-secret-key".
	// Corresponds to the [rules] id field in gitleaks format.
	ID string `toml:"id"`

	// Regex is the regular expression to match against strings.
	// Must be a valid Go regexp syntax string.
	Regex string `toml:"regex"`

	// Description is optional human-readable text. Not used at runtime.
	Description string `toml:"description"`
}

// rulesFile is the top-level structure of a rules.toml file.
type rulesFile struct {
	Rules []Rule `toml:"rules"`
}

// compiledRule pairs a Rule with its compiled regexp, ready for matching.
type compiledRule struct {
	rule Rule
	re   *regexp.Regexp
}

// Match is a single regex hit: which rule fired and what string was matched.
type Match struct {
	// RuleID is the ID field from the matched Rule.
	RuleID string

	// Value is the substring of the input that the regex matched.
	// For secrets scanning purposes this is the credential value itself.
	// The caller (scan package) is responsible for extracting context around it.
	Value string
}

// Matcher holds the compiled rule set and performs matching.
// A Matcher is safe for concurrent use after construction.
type Matcher struct {
	rules []compiledRule
}

// Load parses the TOML content in data, compiles every rule's regex, and
// returns a ready-to-use Matcher.
//
// If any rule contains an invalid regex, Load returns an error identifying
// the offending rule by ID. This is intentionally fatal at startup — a broken
// pattern file should be caught immediately, not silently produce no matches.
func Load(data []byte) (*Matcher, error) {
	var f rulesFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("pattern: failed to parse rules.toml: %w", err)
	}

	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("pattern: rules.toml contains no rules")
	}

	compiled := make([]compiledRule, 0, len(f.Rules))
	for _, r := range f.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("pattern: a rule is missing its id field")
		}
		if r.Regex == "" {
			return nil, fmt.Errorf("pattern: rule %q has an empty regex", r.ID)
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("pattern: rule %q has an invalid regex: %w", r.ID, err)
		}
		compiled = append(compiled, compiledRule{rule: r, re: re})
	}

	return &Matcher{rules: compiled}, nil
}

// Match runs every compiled rule against s and returns one Match per unique
// value found per rule. If no rules match, Match returns nil.
//
// Each rule is evaluated with FindAllString, so multiple distinct matches
// within a single string are returned. Duplicate match values are deduplicated
// to avoid redundant findings from the same string.
func (m *Matcher) Match(s string) []Match {
	var matches []Match
	for _, cr := range m.rules {
		hits := cr.re.FindAllString(s, -1)
		seen := make(map[string]bool, len(hits))
		for _, hit := range hits {
			if seen[hit] {
				continue
			}
			seen[hit] = true
			matches = append(matches, Match{
				RuleID: cr.rule.ID,
				Value:  hit,
			})
		}
	}
	return matches
}

// RuleCount returns the number of rules loaded in this Matcher.
// Used by --verbose startup logging.
func (m *Matcher) RuleCount() int {
	return len(m.rules)
}
