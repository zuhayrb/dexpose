// Package scan orchestrates the APK scanning pipeline: opening APKs,
// extracting strings from all sources, running pattern matching,
// applying ignore rules, and collecting findings.
package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/zuhayrb/dexpose/internal/apk"
	"github.com/zuhayrb/dexpose/internal/ignore"
	"github.com/zuhayrb/dexpose/internal/model"
	"github.com/zuhayrb/dexpose/internal/output"
	"github.com/zuhayrb/dexpose/internal/pattern"
)

// contextSize is the number of characters to include on each side of a
// match when --context is set. Not user-configurable in v1.
const contextSize = 40

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
	Quiet   bool // suppress non-fatal stderr output (warnings, per-APK errors)
	Version string // build version, injected at compile time
}

// Run executes a full scan according to cfg and writes output via cfg.OutputDest.
// It returns:
//
//	0  — scan completed, no non-suppressed findings
//	1  — scan completed, one or more non-suppressed findings present
//	2  — scan failed due to a fatal error
func Run(cfg Config) int {
	// Load patterns.
	matcher, err := loadPatterns(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dexpose: %v\n", err)
		return 2
	}

	if cfg.Verbose {
		printBanner(cfg.Version, matcher.RuleCount())
	}

	// Load ignore file.
	ignoreList, err := loadIgnore(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dexpose: %v\n", err)
		return 2
	}

	// Collect APK paths.
	apkPaths, err := collectAPKPaths(cfg.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dexpose: %v\n", err)
		return 2
	}

	if len(apkPaths) == 0 {
		fmt.Fprintf(os.Stderr, "dexpose: no APK files found at %s\n", cfg.Path)
		return 2
	}

	// Scan APKs.
	var findings []model.Finding
	if len(apkPaths) == 1 {
		// Single APK — no worker pool overhead.
		findings, err = scanAPK(apkPaths[0], matcher, cfg)
	} else {
		// Directory mode — worker pool.
		findings, err = scanAPKPool(apkPaths, matcher, cfg)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dexpose: %v\n", err)
		return 2
	}

	// Apply ignore rules.
	var visible []model.Finding
	for _, f := range findings {
		if !ignoreList.Suppressed(f) {
			visible = append(visible, f)
		}
	}

	// Write output.
	if err := output.Write(visible, cfg.Format, cfg.OutputDest); err != nil {
		fmt.Fprintf(os.Stderr, "dexpose: %v\n", err)
		return 2
	}

	// Verbose summary.
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "dexpose: scanned %d APK(s), %d finding(s)", len(apkPaths), len(visible))
		if suppressed := ignoreList.SuppressedCount(); suppressed > 0 {
			fmt.Fprintf(os.Stderr, ", %d suppressed", suppressed)
		}
		fmt.Fprintln(os.Stderr)
	}

	// Exit code.
	if len(visible) > 0 {
		return 1
	}
	return 0
}

// loadPatterns loads the pattern matcher from --patterns or the embedded default.
func loadPatterns(cfg Config) (*pattern.Matcher, error) {
	if cfg.PatternsFile != "" {
		data, err := os.ReadFile(cfg.PatternsFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read patterns file: %w", err)
		}
		return pattern.Load(data)
	}
	return pattern.Load(defaultPatterns)
}

// loadIgnore loads the ignore list from --ignore, or returns a nil list.
func loadIgnore(cfg Config) (*ignore.List, error) {
	if cfg.IgnoreFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(cfg.IgnoreFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read ignore file: %w", err)
	}
	return ignore.Load(data)
}

// collectAPKPaths returns the list of APK file paths to scan.
// If path is a file, returns a single-element slice.
// If path is a directory, walks it recursively for .apk files.
func collectAPKPaths(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{path}, nil
	}

	var paths []string
	err = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(p)) == ".apk" {
			paths = append(paths, p)
		}
		return nil
	})
	return paths, err
}

// scanAPKPool scans multiple APKs concurrently using a worker pool.
// Per-APK errors are non-fatal: the bad APK is skipped with a warning and
// scanning continues for the remaining APKs.
func scanAPKPool(apkPaths []string, matcher *pattern.Matcher, cfg Config) ([]model.Finding, error) {
	type result struct {
		apkPath  string
		findings []model.Finding
		err      error
	}

	jobs := make(chan string, len(apkPaths))
	results := make(chan result, len(apkPaths))

	workers := runtime.NumCPU()
	if workers > len(apkPaths) {
		workers = len(apkPaths)
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				findings, err := scanAPK(path, matcher, cfg)
				results <- result{path, findings, err}
			}
		}()
	}

	for _, p := range apkPaths {
		jobs <- p
	}
	close(jobs)

	// Wait for all workers to finish, then close results.
	go func() {
		wg.Wait()
		close(results)
	}()

	var all []model.Finding
	for r := range results {
		if r.err != nil {
			// Per-APK error: warn and continue.
			if !cfg.Quiet {
				fmt.Fprintf(os.Stderr, "dexpose: warning: cannot scan %s: %v\n", r.apkPath, r.err)
			}
			continue
		}
		all = append(all, r.findings...)
	}

	return all, nil
}

// scanAPK scans a single APK and returns all findings.
func scanAPK(apkPath string, matcher *pattern.Matcher, cfg Config) ([]model.Finding, error) {
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "dexpose: scanning %s\n", apkPath)
	}

	a, err := apk.Open(apkPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", apkPath, err)
	}
	defer a.Close()

	var findings []model.Finding

	// Scan DEX files.
	dexFiles, err := a.DEXFiles()
	if err != nil {
		// No DEX files is unusual but not fatal — skip.
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "dexpose: warning: %v\n", err)
		}
	} else {
		for i, dex := range dexFiles {
			sourceName := fmt.Sprintf("classes%d.dex", i+1)
			if i == 0 {
				sourceName = "classes.dex"
			}
			dexStrings, err := apk.ExtractStrings(dex)
			if err != nil {
				// Fallback: scan raw binary if DEX extraction fails.
				if cfg.Verbose {
					fmt.Fprintf(os.Stderr, "dexpose: warning: %s: cannot extract DEX strings (%v), scanning raw binary\n", sourceName, err)
				}
				findings = append(findings, scanContent(apkPath, sourceName, string(dex), matcher, cfg)...)
				continue
			}
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "dexpose: %s: %d strings extracted\n", sourceName, len(dexStrings))
			}
			for _, s := range dexStrings {
				findings = append(findings, scanContent(apkPath, sourceName, s, matcher, cfg)...)
			}
		}
	}

	// Decode and scan AndroidManifest.xml.
	manifest, err := a.DecodeManifest()
	if err != nil {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "dexpose: warning: cannot decode AndroidManifest.xml: %v\n", err)
		}
	} else {
		findings = append(findings, scanContent(apkPath, "AndroidManifest.xml", string(manifest), matcher, cfg)...)
	}

	// Scan res/values/strings.xml (present in debug APKs).
	stringsXML, strErr := a.StringsXML()
	if strErr != nil {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "dexpose: warning: %v\n", strErr)
		}
	} else {
		findings = append(findings, scanContent(apkPath, "res/values/strings.xml", string(stringsXML), matcher, cfg)...)
	}

	// Scan compiled string resources from resources.arsc.
	// Release APKs compile res/values/strings.xml into the binary resource table
	// and drop the source file. This catches string values referenced from
	// Java/Kotlin code via R.string.* that DEX scanning alone would miss.
	// Skipped when strings.xml was already scanned to avoid duplicates.
	resStrings, rsErr := a.ResourceStrings()
	if rsErr != nil {
		if !errors.Is(rsErr, os.ErrNotExist) && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "dexpose: warning: cannot extract resource strings: %v\n", rsErr)
		}
	} else if len(resStrings) > 0 && strErr != nil {
		// Serialize as key=value lines for pattern scanning.
		// Sort keys for deterministic output ordering.
		keys := make([]string, 0, len(resStrings))
		for k := range resStrings {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf strings.Builder
		for _, k := range keys {
			buf.WriteString(k)
			buf.WriteByte('=')
			buf.WriteString(resStrings[k])
			buf.WriteByte('\n')
		}
		findings = append(findings, scanContent(apkPath, "resources.arsc", buf.String(), matcher, cfg)...)
	}

	// Scan assets.
	assets, err := a.Assets()
	if err != nil {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "dexpose: warning: %v\n", err)
		}
	} else {
		for assetPath, data := range assets {
			findings = append(findings, scanContent(apkPath, assetPath, string(data), matcher, cfg)...)
		}
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "dexpose: %s: %d finding(s)\n", apkPath, len(findings))
	}

	return findings, nil
}

// scanContent runs all pattern rules against a content string and returns
// findings for every match. When --context is set, each finding includes
// surrounding characters from the source. When --verbose is set, each
// finding is printed to stderr as it is discovered.
func scanContent(apkPath, sourceName, content string, matcher *pattern.Matcher, cfg Config) []model.Finding {
	matches := matcher.Match(content)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]model.Finding, 0, len(matches))
	for _, m := range matches {
		f := model.Finding{
			APK:     apkPath,
			Source:  sourceName,
			Pattern: m.RuleID,
			Match:   m.Value,
			Premium: m.Premium,
		}
		if cfg.Context {
			f.Context = extractContext(content, m.Value)
		}
		if cfg.Verbose {
			matchPreview := m.Value
			if len(matchPreview) > 80 {
				matchPreview = matchPreview[:80] + "..."
			}
			tag := ""
			if m.Premium {
				tag = " [PREMIUM]"
			}
			fmt.Fprintf(os.Stderr, "dexpose: found %s in %s: %s%s\n", m.RuleID, sourceName, matchPreview, tag)
		}
		findings = append(findings, f)
	}
	return findings
}

// extractContext returns a window of surrounding characters around the
// first occurrence of value in content. The window is contextSize characters
// on each side, clamped to the string boundaries.
func extractContext(content, value string) string {
	idx := strings.Index(content, value)
	if idx < 0 {
		// Value not found in content (shouldn't happen, but be safe).
		if len(content) > contextSize*2 {
			return "..." + content[:contextSize*2] + "..."
		}
		return content
	}

	start := idx - contextSize
	if start < 0 {
		start = 0
	}
	end := idx + len(value) + contextSize
	if end > len(content) {
		end = len(content)
	}

	return content[start:end]
}

// asciiBanner is the dexpose logo printed when --verbose is set.
const asciiBanner = `
██████╗ ███████╗██╗  ██╗██████╗  ██████╗ ███████╗███████╗
██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝
██║  ██║█████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗█████╗  
██║  ██║██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║██╔══╝  
██████╔╝███████╗██╔╝ ██╗██║     ╚██████╔╝███████║███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ 
`

// printBanner prints the dexpose logo, version, and rule count to stderr.
func printBanner(version string, ruleCount int) {
	fmt.Fprint(os.Stderr, asciiBanner)
	fmt.Fprintf(os.Stderr, " dexpose %s — %d rules loaded\n\n", version, ruleCount)
}
