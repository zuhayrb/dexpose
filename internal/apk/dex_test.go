package apk_test

import (
	"encoding/binary"
	"testing"

	"github.com/zuhayrb/dexpose/internal/apk"
)

// buildTestDEX constructs a minimal but valid DEX binary containing the
// given strings in its string table. The result is suitable for passing
// to apk.ExtractStrings.
func buildTestDEX(t *testing.T, strings []string) []byte {
	t.Helper()

	// Encode strings as MUTF-8 (ULEB128 length prefix + raw bytes).
	encoded := make([][]byte, len(strings))
	for i, s := range strings {
		encoded[i] = encodeMUTF8String(s)
	}

	// Calculate layout:
	// Header: 0x70 bytes
	// String IDs: len(strings) * 4 bytes (each is a 4-byte offset)
	// String data: concatenated encoded strings
	headerSize := 0x70
	stringIDsSize := len(strings) * 4
	stringIDsOff := uint32(headerSize)
	stringDataOff := uint32(headerSize + stringIDsSize)

	// Build the string offsets.
	offsets := make([]uint32, len(strings))
	off := stringDataOff
	for i, enc := range encoded {
		offsets[i] = off
		off += uint32(len(enc))
	}

	// Build the full DEX binary.
	totalSize := int(stringDataOff)
	for _, enc := range encoded {
		totalSize += len(enc)
	}
	dex := make([]byte, totalSize)

	// Write magic number.
	copy(dex[0:8], []byte("dex\n039\x00"))

	// Write file size.
	binary.LittleEndian.PutUint32(dex[32:], uint32(totalSize))

	// Write header size.
	binary.LittleEndian.PutUint32(dex[36:], uint32(headerSize))

	// Write string_ids_size and string_ids_off.
	binary.LittleEndian.PutUint32(dex[56:], uint32(len(strings)))
	binary.LittleEndian.PutUint32(dex[60:], stringIDsOff)

	// Write string ID offsets.
	for i, o := range offsets {
		off := int(stringIDsOff) + i*4
		binary.LittleEndian.PutUint32(dex[off:], o)
	}

	// Write encoded string data.
	for _, enc := range encoded {
		copy(dex[stringDataOff:], enc)
		stringDataOff += uint32(len(enc))
	}

	return dex
}

// encodeMUTF8String encodes a string as MUTF-8: ULEB128 length prefix
// followed by the raw bytes. For ASCII strings this is identical to
// length-prefixed UTF-8.
func encodeMUTF8String(s string) []byte {
	b := []byte(s)
	length := encodeULEB128(uint64(len(b)))
	result := make([]byte, 0, len(length)+len(b))
	result = append(result, length...)
	result = append(result, b...)
	return result
}

// encodeULEB128 encodes a uint64 as ULEB128.
func encodeULEB128(value uint64) []byte {
	var result []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		result = append(result, b)
		if value == 0 {
			break
		}
	}
	return result
}

// --- ExtractStrings ---

func TestExtractStrings_SingleString(t *testing.T) {
	dex := buildTestDEX(t, []string{"hello"})
	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 string, got %d", len(got))
	}
	if got[0] != "hello" {
		t.Errorf("got %q, want %q", got[0], "hello")
	}
}

func TestExtractStrings_MultipleStrings(t *testing.T) {
	dex := buildTestDEX(t, []string{"alpha", "beta", "gamma"})
	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("want %d strings, got %d", len(want), len(got))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("string[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestExtractStrings_CredentialLikeStrings(t *testing.T) {
	// Simulate strings that look like real credentials found in APKs.
	credStrings := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"sk_\x6cive_ZZZZZZZZZZZZZZZZZZZZZZZZ",
		"xoxb\x2d0000000000-0000000000000-AAAAAAAAAAAAAAAAAAAAAAAA",
		"GOCSPX-abcdefghijklmnopqrstuvwx",
		"-----BEGIN RSA PRIVATE KEY-----",
		"api_key=1234567890abcdefghijklmnop",
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}
	dex := buildTestDEX(t, credStrings)
	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(got) != len(credStrings) {
		t.Fatalf("want %d strings, got %d", len(credStrings), len(got))
	}
	for i, w := range credStrings {
		if got[i] != w {
			t.Errorf("string[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestExtractStrings_EmptyStringTable(t *testing.T) {
	dex := buildTestDEX(t, []string{})
	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want 0 strings, got %d", len(got))
	}
}

func TestExtractStrings_EmptyString(t *testing.T) {
	dex := buildTestDEX(t, []string{""})
	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 string, got %d", len(got))
	}
	if got[0] != "" {
		t.Errorf("got %q, want empty string", got[0])
	}
}

func TestExtractStrings_StringsPreserveOrder(t *testing.T) {
	strings := []string{
		"com.example.app.MainActivity",
		"com.example.app.LoginActivity",
		"https://api.example.com/v1/keys",
		"AKIAIOSFODNN7EXAMPLE",
		"database_password",
	}
	dex := buildTestDEX(t, strings)
	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	for i, w := range strings {
		if got[i] != w {
			t.Errorf("string[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestExtractStrings_TooShort(t *testing.T) {
	_, err := apk.ExtractStrings([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("ExtractStrings should error on file shorter than header")
	}
}

func TestExtractStrings_BadMagic(t *testing.T) {
	dex := make([]byte, 0x70)
	// Write wrong magic.
	copy(dex[0:8], "NOTADEX\n")
	_, err := apk.ExtractStrings(dex)
	if err == nil {
		t.Fatal("ExtractStrings should error on bad magic number")
	}
}

func TestExtractStrings_StringOffsetPastEnd(t *testing.T) {
	// Build a valid header but with a string ID pointing past the end.
	dex := make([]byte, 0x70+8) // header + 2 string IDs
	copy(dex[0:8], []byte("dex\n039\x00"))
	binary.LittleEndian.PutUint32(dex[32:], uint32(len(dex)))
	binary.LittleEndian.PutUint32(dex[36:], 0x70)
	binary.LittleEndian.PutUint32(dex[56:], 2) // 2 string IDs
	binary.LittleEndian.PutUint32(dex[60:], 0x70)
	// Set first string offset to a huge value.
	binary.LittleEndian.PutUint32(dex[0x70:], 0xFFFFFFFF)

	_, err := apk.ExtractStrings(dex)
	if err == nil {
		t.Fatal("ExtractStrings should error when string offset is past end of file")
	}
}

func TestExtractStrings_StringTablePastEnd(t *testing.T) {
	// Header says string_ids_off points past end of file.
	dex := make([]byte, 0x70)
	copy(dex[0:8], []byte("dex\n039\x00"))
	binary.LittleEndian.PutUint32(dex[56:], 1)
	binary.LittleEndian.PutUint32(dex[60:], 0x100) // past end

	_, err := apk.ExtractStrings(dex)
	if err == nil {
		t.Fatal("ExtractStrings should error when string ID table is past end of file")
	}
}

// --- ULEB128 edge cases ---

func TestExtractStrings_LargeString(t *testing.T) {
	// A 300-byte string tests multi-byte ULEB128 length encoding.
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'A'
	}
	dex := buildTestDEX(t, []string{string(long)})
	got, err := apk.ExtractStrings(dex)
	if err != nil {
		t.Fatalf("ExtractStrings: %v", err)
	}
	if len(got) != 1 || len(got[0]) != 300 {
		t.Fatalf("want 1 string of length 300, got %d strings, first length %d", len(got), len(got[0]))
	}
	for i, b := range got[0] {
		if b != 'A' {
			t.Errorf("byte[%d] = %c, want A", i, b)
		}
	}
}
