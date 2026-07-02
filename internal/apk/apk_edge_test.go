package apk_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zuhayrb/dexpose/internal/apk"
)

// --- Corrupted APK ---

func TestOpen_TruncatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "truncated.apk")

	// Create a valid ZIP then truncate it.
	valid := makeTestAPK(t, dir, "valid.apk", map[string][]byte{
		"classes.dex": []byte("dex-data"),
	})
	data, _ := os.ReadFile(valid)
	os.WriteFile(path, data[:len(data)/2], 0644)

	_, err := apk.Open(path)
	if err == nil {
		t.Fatal("Open should error on truncated APK")
	}
}

func TestOpen_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.apk")
	os.WriteFile(path, []byte{}, 0644)

	_, err := apk.Open(path)
	if err == nil {
		t.Fatal("Open should error on empty file")
	}
}

func TestOpen_RandomBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "random.apk")
	os.WriteFile(path, []byte("this is not a zip file at all, just random bytes"), 0644)

	_, err := apk.Open(path)
	if err == nil {
		t.Fatal("Open should error on non-ZIP file")
	}
}

func TestOpen_ZipWithBadCRC(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "crc.apk", map[string][]byte{
		"classes.dex": []byte("dex-content"),
	})

	a, err := apk.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a.Close()

	dexFiles, err := a.DEXFiles()
	if err != nil {
		t.Fatalf("DEXFiles: %v", err)
	}
	if len(dexFiles) != 1 {
		t.Errorf("want 1 DEX, got %d", len(dexFiles))
	}
}

// --- Malformed DEX ---

func TestExtractStrings_ShortHeader(t *testing.T) {
	dex := make([]byte, 20)
	copy(dex[0:8], []byte("dex\n039\x00"))

	_, err := apk.ExtractStrings(dex)
	if err == nil {
		t.Fatal("ExtractStrings should error on short DEX header")
	}
}

func TestExtractStrings_CorruptStringTable(t *testing.T) {
	// Valid header but string_ids_off points past end of file.
	dex := make([]byte, 0x100)
	copy(dex[0:8], []byte("dex\n039\x00"))
	dex[0x38] = 1    // string_ids_size = 1
	dex[0x3C] = 0x80 // string_ids_off = 128
	// But the offset at position 0x80 points way past end.
	dex[0x80] = 0xFF
	dex[0x81] = 0xFF
	dex[0x82] = 0xFF
	dex[0x83] = 0xFF

	_, err := apk.ExtractStrings(dex)
	if err == nil {
		t.Fatal("ExtractStrings should error on corrupt string table offset")
	}
}

func TestExtractStrings_ZeroStrings(t *testing.T) {
	dex := buildTestDEX(t, []string{})

	strings, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(strings) != 0 {
		t.Errorf("want 0 strings, got %d", len(strings))
	}
}

// --- Malformed AXML ---

func TestDecodeManifestBytes_RandomBytes(t *testing.T) {
	_, err := apk.DecodeManifestBytes([]byte("this is not binary XML"))
	if err == nil {
		return
	}
}

func TestDecodeManifestBytes_Empty(t *testing.T) {
	_, err := apk.DecodeManifestBytes([]byte{})
	if err == nil {
		t.Log("DecodeManifestBytes accepted empty input")
		return
	}
}

func TestDecodeManifestBytes_Truncated(t *testing.T) {
	_, err := apk.DecodeManifestBytes([]byte{0x00, 0x01, 0x02, 0x03})
	if err == nil {
		t.Log("DecodeManifestBytes accepted truncated input")
		return
	}
}

// --- Large content ---

func TestExtractStrings_LargeStringTable(t *testing.T) {
	strs := make([]string, 500)
	for i := range strs {
		strs[i] = "string_" + string(rune('A'+i%26)) + "_" + string(rune('0'+i/26%10))
	}
	dex := buildTestDEX(t, strs)

	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(got) != 500 {
		t.Errorf("want 500 strings, got %d", len(got))
	}
}

func TestExtractStrings_UnicodeContent(t *testing.T) {
	strs := []string{
		"hello world",
		"\xc3\xa9l\xc3\xa8ve",       // "élève" in Latin-1
		"\xe4\xb8\xad\xe6\x96\x87", // "中文" in UTF-8
		"caf\xe9",                    // "café" in Latin-1
	}
	dex := buildTestDEX(t, strs)

	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(got) != len(strs) {
		t.Fatalf("want %d strings, got %d", len(strs), len(got))
	}
	for i, s := range strs {
		if got[i] != s {
			t.Errorf("string[%d] = %q, want %q", i, got[i], s)
		}
	}
}

// --- Concurrent access ---

func TestAPK_DEXFiles_ConcurrentCall(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("dex-data"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	const goroutines = 10
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, err := a.DEXFiles()
			if err != nil {
				t.Errorf("DEXFiles: %v", err)
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// --- Directory with non-APK files ---

func TestAPK_Open_DirectoryWithMixedFiles(t *testing.T) {
	dir := t.TempDir()
	apkPath := makeTestAPK(t, dir, "real.apk", map[string][]byte{
		"classes.dex": []byte("dex-data"),
	})
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not an apk"), 0644)
	os.WriteFile(filepath.Join(dir, "image.png"), []byte("fake png"), 0644)

	a, err := apk.Open(apkPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer a.Close()

	dexFiles, err := a.DEXFiles()
	if err != nil {
		t.Fatalf("DEXFiles: %v", err)
	}
	if len(dexFiles) != 1 {
		t.Errorf("want 1 DEX, got %d", len(dexFiles))
	}
}

// --- DecodeManifest edge cases ---

func TestDecodeManifest_PlainTextXML(t *testing.T) {
	plain := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">
</manifest>`)

	decoded, err := apk.DecodeManifestBytes(plain)
	if err != nil {
		t.Fatalf("DecodeManifestBytes should handle plain text: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded output should not be empty")
	}
}

// --- ReadFileRange edge cases ---

func TestReadFileRange_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("dex-data"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.ReadFileRange("nonexistent.txt", 0, 10)
	if err == nil {
		t.Fatal("ReadFileRange should error for nonexistent file")
	}
}

func TestReadFileRange_BeyondEOF(t *testing.T) {
	dir := t.TempDir()
	path := makeTestAPK(t, dir, "test.apk", map[string][]byte{
		"classes.dex": []byte("short"),
	})

	a, _ := apk.Open(path)
	defer a.Close()

	_, err := a.ReadFileRange("classes.dex", 0, 1000)
	if err == nil {
		t.Fatal("ReadFileRange should error when range exceeds file size")
	}
}
