package apk

import (
	"encoding/binary"
	"fmt"
)

// DEX magic prefix: "dex\n" — the version suffix (e.g. "035\0", "039\0")
// varies by API level so we only check the first 4 bytes.
var dexMagicPrefix = []byte("dex\n")

// ExtractStrings extracts all strings from the DEX string table.
// It reads the string_ids section and string_data section from the
// raw DEX bytes and returns the decoded strings in order.
//
// The string data is MUTF-8 encoded in the DEX format. For secrets
// scanning purposes, we treat it as raw bytes — the important thing
// is that credential-like strings (API keys, tokens, etc.) appear
// verbatim in the string table regardless of encoding.
//
// Returns an error if the DEX header is malformed or the string
// table offsets are out of bounds.
func ExtractStrings(dex []byte) ([]string, error) {
	if err := validateDEXHeader(dex); err != nil {
		return nil, err
	}

	stringIDsSize := binary.LittleEndian.Uint32(dex[0x38:])
	stringIDsOff := binary.LittleEndian.Uint32(dex[0x3C:])

	// Bounds check: string ID table must fit within the file.
	endOfIDs := uint64(stringIDsOff) + uint64(stringIDsSize)*4
	if endOfIDs > uint64(len(dex)) {
		return nil, fmt.Errorf("apk: string ID table extends past end of DEX file")
	}

	strings := make([]string, 0, stringIDsSize)
	for i := uint32(0); i < stringIDsSize; i++ {
		offset := binary.LittleEndian.Uint32(dex[stringIDsOff+i*4:])
		s, err := readMUTF8String(dex, uint64(offset))
		if err != nil {
			return nil, fmt.Errorf("apk: string %d: %w", i, err)
		}
		strings = append(strings, s)
	}
	return strings, nil
}

// validateDEXHeader checks the magic number and that critical header
// fields don't point past the end of the byte slice.
func validateDEXHeader(dex []byte) error {
	if len(dex) < 0x70 {
		return fmt.Errorf("apk: DEX file too short (%d bytes, minimum 112)", len(dex))
	}
	if !bytesEqual(dex[:4], dexMagicPrefix) || dex[7] != 0 {
		return fmt.Errorf("apk: invalid DEX magic number")
	}
	return nil
}

// readMUTF8String reads a ULEB128-length-prefixed MUTF-8 string from dex
// at the given offset. For secrets scanning we treat the bytes as-is —
// the important credential strings are pure ASCII.
func readMUTF8String(dex []byte, offset uint64) (string, error) {
	if offset >= uint64(len(dex)) {
		return "", fmt.Errorf("apk: string offset %d past end of file", offset)
	}

	length, n, err := readULEB128(dex[offset:])
	if err != nil {
		return "", fmt.Errorf("apk: cannot read string length at offset %d: %w", offset, err)
	}

	dataStart := offset + n
	dataEnd := dataStart + uint64(length)
	if dataEnd > uint64(len(dex)) {
		return "", fmt.Errorf("apk: string data extends past end of file (offset=%d, length=%d, file_size=%d)", offset, length, len(dex))
	}

	return string(dex[dataStart:dataEnd]), nil
}

// readULEB128 reads a ULEB128-encoded unsigned integer from the byte slice.
// Returns the decoded value, the number of bytes consumed, and any error.
func readULEB128(data []byte) (uint64, uint64, error) {
	var result uint64
	var shift uint
	var i uint64
	for {
		if i >= uint64(len(data)) {
			return 0, 0, fmt.Errorf("apk: unexpected end of data reading ULEB128")
		}
		b := data[i]
		i++
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i, nil
		}
		shift += 7
		if shift > 63 {
			return 0, 0, fmt.Errorf("apk: ULEB128 value too large")
		}
	}
}

// bytesEqual compares two byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
