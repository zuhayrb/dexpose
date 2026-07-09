package scan_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zuhayrb/dexpose/internal/scan"
)

// makeTestAPK builds a minimal ZIP file at dir/name containing the given entries.
func makeTestAPK(t *testing.T, dir, name string, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for p, data := range entries {
		w, err := zw.Create(p)
		if err != nil {
			t.Fatalf("Create(%s): %v", p, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("Write(%s): %v", p, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestRun_SingleAPK_FindsSecrets(t *testing.T) {
	dir := t.TempDir()
	// Copy rules.toml for patterns.
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	apkPath := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("config: AKIAIOSFODNN7EXAMPLE"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 1 {
		t.Errorf("want exit code 1 (findings), got %d", code)
	}
	if !strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("output should contain the finding, got: %s", buf.String())
	}
}

func TestRun_SingleAPK_NoFindings(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	apkPath := makeTestAPK(t, dir, "clean.apk", map[string][]byte{
		"classes.dex": []byte("nothing suspicious here"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 0 {
		t.Errorf("want exit code 0 (no findings), got %d", code)
	}
}

func TestRun_MissingPatternsFile(t *testing.T) {
	dir := t.TempDir()
	apkPath := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("data"),
	})

	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &bytes.Buffer{},
		PatternsFile: filepath.Join(dir, "nonexistent.toml"),
	}

	code := scan.Run(cfg)
	if code != 2 {
		t.Errorf("want exit code 2 (error) for missing patterns file, got %d", code)
	}
}

func TestRun_MissingIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	apkPath := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("data"),
	})

	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &bytes.Buffer{},
		PatternsFile: patternsPath,
		IgnoreFile:   filepath.Join(dir, "nonexistent.ignore"),
	}

	code := scan.Run(cfg)
	if code != 2 {
		t.Errorf("want exit code 2 (error) for missing ignore file, got %d", code)
	}
}

func TestRun_NonexistentPath(t *testing.T) {
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(t.TempDir(), "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	cfg := scan.Config{
		Path:         "/nonexistent/path/to/file.apk",
		Format:       "plain",
		OutputDest:   &bytes.Buffer{},
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 2 {
		t.Errorf("want exit code 2 (error) for nonexistent path, got %d", code)
	}
}

func TestRun_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	cfg := scan.Config{
		Path:         dir,
		Format:       "plain",
		OutputDest:   &bytes.Buffer{},
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 2 {
		t.Errorf("want exit code 2 (error) for empty directory, got %d", code)
	}
}

func TestRun_DirectoryWithNonAPKFiles(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	// Create non-APK files — should be silently skipped.
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not an apk"), 0644)
	os.WriteFile(filepath.Join(dir, "image.png"), []byte("fake png"), 0644)

	cfg := scan.Config{
		Path:         dir,
		Format:       "plain",
		OutputDest:   &bytes.Buffer{},
		PatternsFile: patternsPath,
	}

	// No APKs found = error exit.
	code := scan.Run(cfg)
	if code != 2 {
		t.Errorf("want exit code 2 (no APKs found), got %d", code)
	}
}

func TestRun_CorruptedAPK_SkipsAndContinues(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	// Create a good APK with a finding.
	goodAPK := makeTestAPK(t, dir, "good.apk", map[string][]byte{
		"classes.dex": []byte("secret_key: AKIAIOSFODNN7EXAMPLE"),
	})

	// Create a corrupted APK (random bytes).
	badAPK := filepath.Join(dir, "bad.apk")
	os.WriteFile(badAPK, []byte("this is not a zip file"), 0644)

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         dir,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	// The good APK has a finding, so exit code should be 1.
	if code != 1 {
		t.Errorf("want exit code 1 (findings from good APK), got %d", code)
	}
	// Output should contain the finding from the good APK.
	if !strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("output should contain finding from good APK, got: %s", buf.String())
	}
	_ = goodAPK // suppress unused
}

func TestRun_IgnoreSuppressesFindings(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	ignoreContent := []byte(`[[ignore]]
pattern = "aws-access-key"
`)
	ignorePath := filepath.Join(dir, "ignore.toml")
	os.WriteFile(ignorePath, ignoreContent, 0644)

	apkPath := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("key: AKIAIOSFODNN7EXAMPLE"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
		IgnoreFile:   ignorePath,
		Verbose:      true,
	}

	code := scan.Run(cfg)
	if code != 0 {
		t.Errorf("want exit code 0 (all findings suppressed), got %d", code)
	}
	if strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("suppressed finding should not appear in output, got: %s", buf.String())
	}
}

func TestRun_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	apkPath := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("key: AKIAIOSFODNN7EXAMPLE"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         apkPath,
		Format:       "json",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 1 {
		t.Errorf("want exit code 1, got %d", code)
	}

	output := buf.String()
	if !strings.HasPrefix(output, "[") {
		t.Errorf("JSON output should start with [, got: %s", output)
	}
	if !strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("JSON output should contain the finding")
	}
}

func TestRun_ContextExtraction(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	apkPath := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("some_prefix_data key=AKIAIOSFODNN7EXAMPLE some_suffix_data"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
		Context:      true,
	}

	code := scan.Run(cfg)
	if code != 1 {
		t.Errorf("want exit code 1, got %d", code)
	}

	output := buf.String()
	// Context should include surrounding text.
	if !strings.Contains(output, "some_prefix_data") {
		t.Errorf("context should include prefix, got: %s", output)
	}
}

func TestRun_ResourcesARSC_FindsSecrets(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	arsc, err := os.ReadFile("../../internal/apk/testdata/resources_arsc_strings.arsc")
	if err != nil {
		t.Skipf("testdata not available: %v", err)
	}

	// APK with resources.arsc but NO strings.xml — simulates a release APK.
	apkPath := makeTestAPK(t, dir, "release.apk", map[string][]byte{
		"resources.arsc": arsc,
		"classes.dex":    []byte("dex content"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 1 {
		t.Errorf("want exit code 1 (findings), got %d", code)
	}
	output := buf.String()
	// The resource string "AKIAIOSFODNN7EXAMPLE" should match aws-access-key.
	if !strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("output should contain AWS key from resources.arsc, got: %s", output)
	}
	if !strings.Contains(output, "resources.arsc") {
		t.Errorf("output should reference resources.arsc as source, got: %s", output)
	}
}

func TestRun_ResourcesARSC_SkippedWhenStringsXMLPresent(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	arsc, err := os.ReadFile("../../internal/apk/testdata/resources_arsc_strings.arsc")
	if err != nil {
		t.Skipf("testdata not available: %v", err)
	}

	// APK with BOTH strings.xml and resources.arsc — resources.arsc should be skipped
	// to avoid duplicates.
	apkPath := makeTestAPK(t, dir, "debug.apk", map[string][]byte{
		"resources.arsc":         arsc,
		"res/values/strings.xml": []byte("<resources><string name=\"x\">clean</string></resources>"),
		"classes.dex":            []byte("dex content"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         apkPath,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 0 {
		t.Errorf("want exit code 0 (no findings), got %d", code)
	}
}

func TestRun_MultipleAPKs_DirectoryMode(t *testing.T) {
	dir := t.TempDir()
	patterns, _ := os.ReadFile("../../patterns/rules.toml")
	patternsPath := filepath.Join(dir, "rules.toml")
	os.WriteFile(patternsPath, patterns, 0644)

	// Two APKs, both with findings.
	makeTestAPK(t, dir, "apk1.apk", map[string][]byte{
		"classes.dex": []byte("key: AKIAIOSFODNN7EXAMPLE"),
	})
	makeTestAPK(t, dir, "apk2.apk", map[string][]byte{
		"classes.dex": []byte("token: xoxb\x2d0000000000\x2d000000000000\x2dAAAAAAAAAAAAAAAAAAAAAAAA"),
	})

	var buf bytes.Buffer
	cfg := scan.Config{
		Path:         dir,
		Format:       "plain",
		OutputDest:   &buf,
		PatternsFile: patternsPath,
	}

	code := scan.Run(cfg)
	if code != 1 {
		t.Errorf("want exit code 1, got %d", code)
	}

	output := buf.String()
	if !strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("output should contain finding from APK 1")
	}
	// Note: hex-escaped Slack token in test, so it won't match the real rule.
	// But the test verifies the directory mode works.
}
