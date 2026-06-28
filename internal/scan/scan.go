package scan

import (
	"io"
)

// Finding is the core data structure produced by a scan and consumed by
// the output and ignore packages. No package mutates a Finding after creation.
type Finding struct {
	APK     string // path to the APK file on disk
	Source  string // source file within the APK (e.g. "classes.dex", "assets/config.js")
	Pattern string // name of the matched pattern rule
	Match   string // the matched string value
	Context string // surrounding characters; populated only when Config.Context is true
}

// Config holds all user-supplied configuration for a scan run.
// It is constructed in main.go from parsed flags and passed into Run.
type Config struct {
	// Input
	Path string // single APK file or directory to walk

	// Output
	Format     string    // "plain" or "json"
	OutputDest io.Writer // resolved writer (stdout or opened file)

	// Patterns
	PatternsFile string // path to custom rules.toml; empty means use bundled set

	// Ignore
	IgnoreFile string // path to ignore file; empty means no suppression

	// Behaviour
	Context bool // include surrounding characters in findings
	Verbose bool // print progress and per-file metadata
}

// Run executes a full scan according to cfg and writes output via cfg.OutputDest.
// It returns:
//
//	0  — scan completed, no non-suppressed findings
//	1  — scan completed, one or more non-suppressed findings present
//	2  — scan failed due to a fatal error
//
// Run is a stub; real orchestration is implemented in Phase 5.
func Run(cfg Config) int {
	// Phase 5 will implement worker pool, per-source goroutines, finding
	// collection, ignore application, and output dispatch.
	_ = cfg
	return 0
}
