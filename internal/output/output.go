// Package output formats and writes scan findings to a destination.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/zuhayrb/dexpose/internal/model"
)

// Write writes findings to w in the given format ("plain", "json", or "table").
// An empty findings slice produces no output for plain format and an
// empty JSON array for json format.
// If format is "table", colors are enabled only when isTTY is true.
func Write(findings []model.Finding, format string, w io.Writer, isTTY bool) error {
	switch format {
	case "json":
		return writeJSON(findings, w)
	case "table":
		return writeTable(findings, w, isTTY)
	default:
		return writePlain(findings, w)
	}
}

// writePlain writes one line per finding.
func writePlain(findings []model.Finding, w io.Writer) error {
	for _, f := range findings {
		label := ""
		if f.Premium {
			label = "[PREMIUM]\t"
		}
		line := fmt.Sprintf("%s%s\t%s\t%s\t%s", label, f.APK, f.Source, f.Pattern, f.Match)
		if f.Context != "" {
			line += "\t" + f.Context
		}
		line += "\n"
		if _, err := io.WriteString(w, line); err != nil {
			return err
		}
	}
	return nil
}

// writeTable writes findings as a styled table with headers and colored severity.
func writeTable(findings []model.Finding, w io.Writer, isTTY bool) error {
	if len(findings) == 0 {
		// Still print headers for consistency
		fmt.Fprintln(w, headerRow(isTTY))
		return nil
	}

	// Calculate column widths
	maxType := len("TYPE")
	maxLoc := len("LOCATION")
	maxMatch := len("MATCH")
	for _, f := range findings {
		if len(f.Pattern) > maxType {
			maxType = len(f.Pattern)
		}
		if len(f.Source) > maxLoc {
			maxLoc = len(f.Source)
		}
		matchLen := len(f.Match)
		if matchLen > maxMatch {
			maxMatch = matchLen
		}
	}

	// Cap columns to reasonable max widths
	const maxTypeW, maxLocW, maxMatchW = 32, 40, 60
	if maxType > maxTypeW {
		maxType = maxTypeW
	}
	if maxLoc > maxLocW {
		maxLoc = maxLocW
	}
	if maxMatch > maxMatchW {
		maxMatch = maxMatchW
	}

	// Print header
	fmt.Fprintln(w, headerRow(isTTY))

	// Print rows
	for _, f := range findings {
		sev := SeverityFromPattern(f.Pattern)
		sevCell := severityCell(sev, isTTY)
		typeCell := truncate(f.Pattern, maxType)
		locCell := truncate(f.Source, maxLoc)
		matchCell := truncate(f.Match, maxMatch)

		line := fmt.Sprintf("%s  %-*s  %-*s  %s",
			sevCell, maxType, typeCell, maxLoc, locCell, matchCell)
		fmt.Fprintln(w, line)
	}
	return nil
}

func headerRow(isTTY bool) string {
	if isTTY {
		return fmt.Sprintf("%-8s  %-*s  %s",
			bold("SEVERITY"), 32, bold("TYPE"), bold("MATCH"))
	}
	return fmt.Sprintf("%-8s  %-*s  %s", "SEVERITY", 32, "TYPE", "MATCH")
}

func severityCell(sev string, isTTY bool) string {
	if !isTTY {
		return fmt.Sprintf("%-8s", sev)
	}
	switch sev {
	case "HIGH":
		return red(fmt.Sprintf("%-8s", sev))
	case "MEDIUM":
		return yellow(fmt.Sprintf("%-8s", sev))
	case "LOW":
		return dim(fmt.Sprintf("%-8s", sev))
	default:
		return fmt.Sprintf("%-8s", sev)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// writeJSON collects all findings and writes a JSON array.
func writeJSON(findings []model.Finding, w io.Writer) error {
	type jsonFinding struct {
		APK     string `json:"apk"`
		Source  string `json:"source"`
		Pattern string `json:"pattern"`
		Match   string `json:"match"`
		Context string `json:"context,omitempty"`
		Premium bool   `json:"premium,omitempty"`
	}

	items := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		items = append(items, jsonFinding{
			APK:     f.APK,
			Source:  f.Source,
			Pattern: f.Pattern,
			Match:   f.Match,
			Context: f.Context,
			Premium: f.Premium,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}