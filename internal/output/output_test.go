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

	err := output.Write(findings, "plain", &buf)
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

	err := output.Write(findings, "plain", &buf)
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

	err := output.Write(findings, "plain", &buf)
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
	err := output.Write(nil, "plain", &buf)
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

	err := output.Write(findings, "json", &buf)
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

	err := output.Write(findings, "json", &buf)
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

	err := output.Write(findings, "json", &buf)
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
	err := output.Write(nil, "json", &buf)
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

	err := output.Write(findings, "json", &buf)
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
	err := output.Write(findings, "unknown", &buf)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Plain format produces tab-separated lines, not JSON.
	if buf.Bytes()[0] == '{' {
		t.Error("unknown format should default to plain, not JSON")
	}
}
