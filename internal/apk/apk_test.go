package apk_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/zuhayrb/dexpose/internal/apk"
)

// makeTestAPK builds a minimal ZIP file at dir/name containing the given
// entries. Each entry is a map of relative path → content bytes.
func makeTestAPK(t *testing.T, dir, name string, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for path, data := range entries {
		w, err := zw.Create(path)
		if err != nil {
			t.Fatalf("Create(%s): %v", path, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("Write(%s): %v", path, err)
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

// --- Open ---

func TestOpen_ValidAPK(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("dex-content"),
	})

	a, err := apk.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a.Close()

	if got := a.Path(); got != path {
		t.Errorf("Path() = %q, want %q", got, path)
	}
}

func TestOpen_NonExistentFile(t *testing.T) {
	_, err := apk.Open("/nonexistent/file.apk")
	if err == nil {
		t.Fatal("Open should return error for non-existent file")
	}
}

func TestOpen_NotAZIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-an-apk.apk")
	os.WriteFile(path, []byte("this is not a zip file"), 0644)

	_, err := apk.Open(path)
	if err == nil {
		t.Fatal("Open should return error for non-ZIP file")
	}
}

// --- DEXFiles ---

func TestDEXFiles_SingleDEX(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex":       []byte("dex1"),
		"AndroidManifest.xml": []byte("manifest"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	dexFiles, err := a.DEXFiles()
	if err != nil {
		t.Fatalf("DEXFiles: %v", err)
	}
	if len(dexFiles) != 1 {
		t.Fatalf("DEXFiles: want 1, got %d", len(dexFiles))
	}
	if !bytes.Equal(dexFiles[0], []byte("dex1")) {
		t.Errorf("DEXFiles[0] = %q, want %q", dexFiles[0], "dex1")
	}
}

func TestDEXFiles_MultipleDEX(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex":  []byte("dex1"),
		"classes2.dex": []byte("dex2"),
		"classes3.dex": []byte("dex3"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	dexFiles, err := a.DEXFiles()
	if err != nil {
		t.Fatalf("DEXFiles: %v", err)
	}
	if len(dexFiles) != 3 {
		t.Fatalf("DEXFiles: want 3, got %d", len(dexFiles))
	}
	if !bytes.Equal(dexFiles[0], []byte("dex1")) {
		t.Errorf("DEXFiles[0] = %q, want %q", dexFiles[0], "dex1")
	}
	if !bytes.Equal(dexFiles[1], []byte("dex2")) {
		t.Errorf("DEXFiles[1] = %q, want %q", dexFiles[1], "dex2")
	}
	if !bytes.Equal(dexFiles[2], []byte("dex3")) {
		t.Errorf("DEXFiles[2] = %q, want %q", dexFiles[2], "dex3")
	}
}

func TestDEXFiles_NoDEX(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"AndroidManifest.xml": []byte("manifest"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.DEXFiles()
	if err == nil {
		t.Fatal("DEXFiles should return error when no DEX files exist")
	}
}

func TestDEXFiles_IgnoresNonDEX(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex":        []byte("dex1"),
		"resources.arsc":     []byte("resources"),
		"assets/config.json": []byte("{}"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	dexFiles, err := a.DEXFiles()
	if err != nil {
		t.Fatalf("DEXFiles: %v", err)
	}
	if len(dexFiles) != 1 {
		t.Errorf("DEXFiles: want 1 (only classes.dex), got %d", len(dexFiles))
	}
}

// --- Manifest ---

func TestManifest_Present(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"AndroidManifest.xml": []byte("binary-xml-content"),
		"classes.dex":         []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	data, err := a.Manifest()
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if !bytes.Equal(data, []byte("binary-xml-content")) {
		t.Errorf("Manifest() = %q, want %q", data, "binary-xml-content")
	}
}

func TestManifest_Missing(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.Manifest()
	if err == nil {
		t.Fatal("Manifest should return error when AndroidManifest.xml is missing")
	}
}

// --- StringsXML ---

func TestStringsXML_Present(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"res/values/strings.xml": []byte("<resources><string name=\"key\">value</string></resources>"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	data, err := a.StringsXML()
	if err != nil {
		t.Fatalf("StringsXML: %v", err)
	}
	if !bytes.Equal(data, []byte("<resources><string name=\"key\">value</string></resources>")) {
		t.Errorf("StringsXML() content mismatch")
	}
}

func TestStringsXML_Missing(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.StringsXML()
	if err == nil {
		t.Fatal("StringsXML should return error when res/values/strings.xml is missing")
	}
}

// --- Assets ---

func TestAssets_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"assets/config.json":   []byte("{}"),
		"assets/vendor.bundle": []byte("js-content"),
		"classes.dex":          []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	assets, err := a.Assets()
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("Assets: want 2 entries, got %d", len(assets))
	}
	if !bytes.Equal(assets["assets/config.json"], []byte("{}")) {
		t.Error("assets/config.json content mismatch")
	}
	if !bytes.Equal(assets["assets/vendor.bundle"], []byte("js-content")) {
		t.Error("assets/vendor.bundle content mismatch")
	}
}

func TestAssets_NoAssets(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	assets, err := a.Assets()
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("Assets: want 0 entries, got %d", len(assets))
	}
}

func TestAssets_IgnoresNonAssetFiles(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"assets/config.json":  []byte("{}"),
		"res/values/strings.xml": []byte("<xml/>"),
		"classes.dex":         []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	assets, err := a.Assets()
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	if len(assets) != 1 {
		t.Errorf("Assets: want 1 entry, got %d", len(assets))
	}
}

// --- SourceType ---

func TestSourceType_String(t *testing.T) {
	cases := []struct {
		st   apk.SourceType
		want string
	}{
		{apk.SourceDEX, "DEX"},
		{apk.SourceManifest, "AndroidManifest.xml"},
		{apk.SourceStringsXML, "strings.xml"},
		{apk.SourceAsset, "asset"},
	}
	for _, tc := range cases {
		if got := tc.st.String(); got != tc.want {
			t.Errorf("SourceType(%d).String() = %q, want %q", tc.st, got, tc.want)
		}
	}
}

// --- Full APK scenario ---

func TestFullAPK_AllSources(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "real.apk", map[string][]byte{
		"classes.dex":          []byte("dex-data"),
		"classes2.dex":         []byte("dex2-data"),
		"AndroidManifest.xml":  []byte("manifest-data"),
		"res/values/strings.xml": []byte("<resources/>"),
		"assets/app.js":        []byte("var x = 1;"),
		"assets/style.css":     []byte("body {}"),
		"resources.arsc":       []byte("resources"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	dexFiles, err := a.DEXFiles()
	if err != nil {
		t.Fatalf("DEXFiles: %v", err)
	}
	if len(dexFiles) != 2 {
		t.Errorf("DEXFiles: want 2, got %d", len(dexFiles))
	}

	manifest, err := a.Manifest()
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if !bytes.Equal(manifest, []byte("manifest-data")) {
		t.Error("Manifest content mismatch")
	}

	strings, err := a.StringsXML()
	if err != nil {
		t.Fatalf("StringsXML: %v", err)
	}
	if !bytes.Equal(strings, []byte("<resources/>")) {
		t.Error("StringsXML content mismatch")
	}

	assets, err := a.Assets()
	if err != nil {
		t.Fatalf("Assets: %v", err)
	}
	if len(assets) != 2 {
		t.Errorf("Assets: want 2, got %d", len(assets))
	}
}

// --- DecodeManifest ---

func TestDecodeManifest_BinaryAXML(t *testing.T) {
	// Use a real AXML binary from the apkparser testdata.
	axml, err := os.ReadFile("testdata/AndroidManifest.axml")
	if err != nil {
		t.Skipf("testdata not available: %v", err)
	}

	decoded, err := apk.DecodeManifestBytes(axml)
	if err != nil {
		t.Fatalf("DecodeManifestBytes: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("DecodeManifestBytes returned empty output")
	}
	// The decoded output should be valid XML (starts with <).
	if decoded[0] != '<' {
		t.Errorf("decoded manifest should start with '<', got %q", decoded[0])
	}
}

func TestDecodeManifest_PlainTextManifest(t *testing.T) {
	// Some APKs have a plain-text AndroidManifest.xml.
	plain := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">
</manifest>`)

	decoded, err := apk.DecodeManifestBytes(plain)
	if err != nil {
		t.Fatalf("DecodeManifestBytes should handle plain text; got: %v", err)
	}
	// Should return the raw bytes when ErrPlainTextManifest is returned.
	if !bytes.Equal(decoded, plain) {
		t.Errorf("plain text manifest should be returned as-is")
	}
}

func TestDecodeManifest_MissingManifest(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "no-manifest.apk", map[string][]byte{
		"classes.dex": []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.DecodeManifest()
	if err == nil {
		t.Fatal("DecodeManifest should error when AndroidManifest.xml is missing")
	}
}

// --- ResourceTable ---

func TestResourceTable_Present(t *testing.T) {
	arsc, err := os.ReadFile("testdata/resources.arsc")
	if err != nil {
		t.Skipf("testdata/resources.arsc not available: %v", err)
	}

	dir := t.TempDir()
	path := makeTestAPK(t, dir, "with-arsc.apk", map[string][]byte{
		"resources.arsc": arsc,
		"classes.dex":    []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	table, err := a.ResourceTable()
	if err != nil {
		t.Fatalf("ResourceTable() returned error: %v", err)
	}
	if table == nil {
		t.Fatal("ResourceTable() returned nil")
	}
}

func TestResourceTable_Missing(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "no-arsc.apk", map[string][]byte{
		"classes.dex": []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.ResourceTable()
	if err == nil {
		t.Fatal("ResourceTable() should error when resources.arsc is missing")
	}
}

func TestResourceTable_Corrupted(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "corrupt-arsc.apk", map[string][]byte{
		"resources.arsc": []byte("this is not a valid resources.arsc"),
		"classes.dex":    []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.ResourceTable()
	if err == nil {
		t.Fatal("ResourceTable() should error on corrupted resources.arsc")
	}
}

// --- DecodeManifest with resource resolution ---

func TestDecodeManifest_WithResources_NoARSC(t *testing.T) {
	// APK without resources.arsc — DecodeManifest falls back to nil resources.
	axml, err := os.ReadFile("testdata/AndroidManifest.axml")
	if err != nil {
		t.Skipf("testdata not available: %v", err)
	}

	dir := t.TempDir()
	path := makeTestAPK(t, dir, "no-arsc.apk", map[string][]byte{
		"AndroidManifest.xml": axml,
		"classes.dex":         []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	decoded, err := a.DecodeManifest()
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("DecodeManifest returned empty output")
	}
	if decoded[0] != '<' {
		t.Errorf("decoded manifest should start with '<', got %q", decoded[0])
	}
}

func TestDecodeManifest_WithResources_ARSC(t *testing.T) {
	// APK with both AXML manifest and resources.arsc.
	axml, err := os.ReadFile("testdata/AndroidManifest.axml")
	if err != nil {
		t.Skipf("testdata/AndroidManifest.axml not available: %v", err)
	}
	arsc, err := os.ReadFile("testdata/resources.arsc")
	if err != nil {
		t.Skipf("testdata/resources.arsc not available: %v", err)
	}

	dir := t.TempDir()
	path := makeTestAPK(t, dir, "with-resources.apk", map[string][]byte{
		"AndroidManifest.xml": axml,
		"resources.arsc":      arsc,
		"classes.dex":         []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	decoded, err := a.DecodeManifest()
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("DecodeManifest returned empty output")
	}
	if decoded[0] != '<' {
		t.Errorf("decoded manifest should start with '<', got %q", decoded[0])
	}
}

func TestDecodeManifest_WithResources_Fallback(t *testing.T) {
	// Corrupted resources.arsc — DecodeManifest falls back gracefully.
	axml, err := os.ReadFile("testdata/AndroidManifest.axml")
	if err != nil {
		t.Skipf("testdata not available: %v", err)
	}

	dir := t.TempDir()
	path := makeTestAPK(t, dir, "corrupt-resources.apk", map[string][]byte{
		"AndroidManifest.xml": axml,
		"resources.arsc":      []byte("garbage"),
		"classes.dex":         []byte("dex1"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	decoded, err := a.DecodeManifest()
	if err != nil {
		t.Fatalf("DecodeManifest should fall back on corrupted resources.arsc, got: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("DecodeManifest returned empty output")
	}
	if decoded[0] != '<' {
		t.Errorf("decoded manifest should start with '<', got %q", decoded[0])
	}
}
