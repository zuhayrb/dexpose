package output_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/zuhayrb/dexpose/internal/model"
	"github.com/zuhayrb/dexpose/internal/output"
)

func TestWritePlain_SingleFinding(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "classes.dex", Pattern: "aws-access-key", Match: "AKIA123"},
	}

	err := output.Write(findings, "plain", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := buf.String()
	if got != "test.apk\tclasses.dex\taws-access-key\tAKIA123\n" {
		t.Errorf("unexpected output: %q", got)
	}
}

func TestWritePlain_WithContext(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "classes.dex", Pattern: "aws-access-key", Match: "AKIA123", Context: "...key=AKIA123..."},
	}

	err := output.Write(findings, "plain", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := buf.String()
	want := "test.apk\tclasses.dex\taws-access-key\tAKIA123\t...key=AKIA123...\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWritePlain_MultipleFindings(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "a.apk", Source: "classes.dex", Pattern: "rule-1", Match: "val1"},
		{APK: "a.apk", Source: "assets/config.js", Pattern: "rule-2", Match: "val2"},
	}

	err := output.Write(findings, "plain", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
}

func TestWritePlain_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := output.Write(nil, "plain", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("empty findings should produce no output, got %q", buf.String())
	}
}

func TestWriteJSON_SingleFinding(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "classes.dex", Pattern: "aws-access-key", Match: "AKIA123"},
	}

	err := output.Write(findings, "json", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var items []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	if items[0]["apk"] != "test.apk" {
		t.Errorf("apk = %v, want test.apk", items[0]["apk"])
	}
	if items[0]["pattern"] != "aws-access-key" {
		t.Errorf("pattern = %v, want aws-access-key", items[0]["pattern"])
	}
}

func TestWriteJSON_WithContext(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "classes.dex", Pattern: "rule", Match: "val", Context: "surrounding"},
	}

	err := output.Write(findings, "json", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var items []map[string]interface{}
	json.Unmarshal(buf.Bytes(), &items)
	if items[0]["context"] != "surrounding" {
		t.Errorf("context = %v, want surrounding", items[0]["context"])
	}
}

func TestWriteJSON_EmptyContextOmitted(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "classes.dex", Pattern: "rule", Match: "val"},
	}

	err := output.Write(findings, "json", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var items []map[string]interface{}
	json.Unmarshal(buf.Bytes(), &items)
	_, hasContext := items[0]["context"]
	if hasContext {
		t.Error("empty context should be omitted from JSON output")
	}
}

func TestWriteJSON_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := output.Write(nil, "json", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var items []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("want empty array, got %d items", len(items))
	}
}

func TestWriteJSON_MultipleFindings(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "a.apk", Source: "classes.dex", Pattern: "r1", Match: "v1"},
		{APK: "b.apk", Source: "assets/x.js", Pattern: "r2", Match: "v2"},
	}

	err := output.Write(findings, "json", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	var items []map[string]interface{}
	json.Unmarshal(buf.Bytes(), &items)
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d", len(items))
	}
}

func TestWrite_DefaultFormatIsPlain(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "c.dex", Pattern: "r", Match: "v"},
	}

	// "unknown" format should fall through to plain.
	err := output.Write(findings, "unknown", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Plain format produces tab-separated lines, not JSON.
	if buf.Bytes()[0] == '{' {
		t.Error("unknown format should default to plain, not JSON")
	}
}

func TestWriteTable_SingleFinding(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "classes.dex", Pattern: "aws-access-key", Match: "AKIA123"},
	}

	err := output.Write(findings, "table", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := buf.String()
	// Check for header
	if !contains(got, "SEVERITY") || !contains(got, "TYPE") || !contains(got, "MATCH") {
		t.Errorf("missing header: %q", got)
	}
	// Check for severity
	if !contains(got, "HIGH") {
		t.Errorf("missing HIGH severity: %q", got)
	}
	// Check for finding
	if !contains(got, "aws-access-key") || !contains(got, "AKIA123") {
		t.Errorf("missing finding data: %q", got)
	}
}

func TestWriteTable_WithSeverityMapping(t *testing.T) {
	var buf bytes.Buffer
	findings := []model.Finding{
		{APK: "test.apk", Source: "classes.dex", Pattern: "aws-access-key", Match: "AKIA123"}, // HIGH
		{APK: "test.apk", Source: "assets/x.js", Pattern: "slack-webhook-url", Match: "https://..."}, // MEDIUM
		{APK: "test.apk", Source: "classes.dex", Pattern: "generic-api-key", Match: "abc123"}, // LOW
	}

	err := output.Write(findings, "table", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := buf.String()
	// Check severity mapping
	if !contains(got, "HIGH") {
		t.Errorf("missing HIGH: %q", got)
	}
	if !contains(got, "MEDIUM") {
		t.Errorf("missing MEDIUM: %q", got)
	}
	if !contains(got, "LOW") {
		t.Errorf("missing LOW: %q", got)
	}
}

func TestWriteTable_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	err := output.Write(nil, "table", &buf, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := buf.String()
	// Should still print header
	if !contains(got, "SEVERITY") || !contains(got, "TYPE") || !contains(got, "MATCH") {
		t.Errorf("missing header on empty: %q", got)
	}
}

func TestSeverityFromPattern(t *testing.T) {
	tests := []struct {
		patternID string
		expected  string
	}{
		{"aws-access-key", "HIGH"},
		{"stripe-secret-key", "HIGH"},
		{"slack-webhook-url", "MEDIUM"},
		{"generic-api-key", "LOW"},
		{"unknown-pattern", "MEDIUM"}, // default
	}
	for _, tc := range tests {
		got := output.SeverityFromPattern(tc.patternID)
		if got != tc.expected {
			t.Errorf("SeverityFromPattern(%q) = %q, want %q", tc.patternID, got, tc.expected)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
