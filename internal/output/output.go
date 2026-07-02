// Package output formats and writes scan findings to a destination.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/zuhayrb/dexpose/internal/model"
)

// Write writes findings to w in the given format ("plain" or "json").
// An empty findings slice produces no output for plain format and an
// empty JSON array for json format.
func Write(findings []model.Finding, format string, w io.Writer) error {
	switch format {
	case "json":
		return writeJSON(findings, w)
	default:
		return writePlain(findings, w)
	}
}

// writePlain writes one line per finding.
func writePlain(findings []model.Finding, w io.Writer) error {
	for _, f := range findings {
		line := fmt.Sprintf("%s\t%s\t%s\t%s", f.APK, f.Source, f.Pattern, f.Match)
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

// writeJSON collects all findings and writes a JSON array.
func writeJSON(findings []model.Finding, w io.Writer) error {
	type jsonFinding struct {
		APK     string `json:"apk"`
		Source  string `json:"source"`
		Pattern string `json:"pattern"`
		Match   string `json:"match"`
		Context string `json:"context,omitempty"`
	}

	items := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		items = append(items, jsonFinding{
			APK:     f.APK,
			Source:  f.Source,
			Pattern: f.Pattern,
			Match:   f.Match,
			Context: f.Context,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(items)
}
