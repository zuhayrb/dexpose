// Package ignore parses an ignore file and determines whether a given
// Finding should be suppressed from output and from contributing to the
// scan's exit code.
//
// The package is intentionally narrow: it knows nothing about scanning,
// patterns, or output formats. Its only job is "given a finding, should it
// be hidden?"
package ignore

import (
	"fmt"
	"sync/atomic"

	"github.com/BurntSushi/toml"
	"github.com/zuhayrb/dexpose/internal/scan"
)

// Entry is a single suppression rule from an ignore file.
//
// At least one field must be set. If more than one field is set, all set
// fields must match a Finding for the entry to suppress it — fields within
// a single entry combine with AND, e.g.
//
//	[[ignore]]
//	pattern = "generic-api-key"
//	source  = "assets/vendor.bundle.js"
//
// only suppresses generic-api-key findings from that one source, not the
// pattern everywhere or that source for every pattern. Unset fields ("")
// are treated as "don't care" and never constrain the match.
type Entry struct {
	// Pattern, if set, must equal the Finding's Pattern field exactly.
	Pattern string `toml:"pattern"`

	// Value, if set, must equal the Finding's Match field exactly.
	Value string `toml:"value"`

	// Source, if set, must equal the Finding's Source field exactly.
	Source string `toml:"source"`
}

// ignoreFile is the top-level structure of an ignore TOML file.
type ignoreFile struct {
	Ignore []Entry `toml:"ignore"`
}

// List holds a parsed set of ignore entries and counts how many findings it
// has suppressed so far via Suppressed.
//
// A List is safe for concurrent use after construction: entries is read-only
// post-Load, and suppressedCount is updated atomically. A nil *List is also
// safe to use — Suppressed always returns false and SuppressedCount always
// returns 0 — so callers don't need a conditional when no ignore file was
// provided.
type List struct {
	entries         []Entry
	suppressedCount atomic.Int64
}

// Load parses the TOML content in data and returns a ready-to-use List.
//
// Load is fatal on malformed input: invalid TOML, or any [[ignore]] entry
// that sets none of pattern, value, or source. An entry matching nothing
// would silently suppress nothing while looking like a suppression rule,
// which is far more likely to be a typo than an intentional no-op — so it is
// caught immediately rather than producing a confusing, silently-inert rule.
//
// An ignore file with zero [[ignore]] entries is valid and produces a List
// that suppresses nothing.
func Load(data []byte) (*List, error) {
	var f ignoreFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("ignore: failed to parse ignore file: %w", err)
	}

	for i, e := range f.Ignore {
		if e.Pattern == "" && e.Value == "" && e.Source == "" {
			return nil, fmt.Errorf("ignore: entry %d sets none of pattern, value, or source", i+1)
		}
	}

	return &List{entries: f.Ignore}, nil
}

// Suppressed reports whether f matches any ignore entry in l. If it does,
// the suppression count is incremented and Suppressed returns true.
//
// An entry matches f when every field the entry sets is exactly equal
// (case-sensitive, no wildcards) to the corresponding field on f. A List
// suppresses f if any single entry matches — entries combine with OR.
//
// Calling Suppressed on a nil *List always returns false.
func (l *List) Suppressed(f scan.Finding) bool {
	if l == nil {
		return false
	}

	for _, e := range l.entries {
		if entryMatches(e, f) {
			l.suppressedCount.Add(1)
			return true
		}
	}
	return false
}

// entryMatches reports whether every field e sets equals the corresponding
// field on f. Unset fields on e never block a match.
func entryMatches(e Entry, f scan.Finding) bool {
	if e.Pattern != "" && e.Pattern != f.Pattern {
		return false
	}
	if e.Value != "" && e.Value != f.Match {
		return false
	}
	if e.Source != "" && e.Source != f.Source {
		return false
	}
	return true
}

// SuppressedCount returns the number of findings suppressed so far via calls
// to Suppressed. Used by the --verbose summary line.
//
// Calling SuppressedCount on a nil *List always returns 0.
func (l *List) SuppressedCount() int {
	if l == nil {
		return 0
	}
	return int(l.suppressedCount.Load())
}

// EntryCount returns the number of ignore entries loaded into l.
//
// Calling EntryCount on a nil *List always returns 0.
func (l *List) EntryCount() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}
