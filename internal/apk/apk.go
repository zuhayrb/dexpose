// Package apk opens an APK (ZIP) archive and provides access to its
// internal sources for secrets scanning.
//
// The package is intentionally narrow: it knows nothing about pattern
// matching, output formats, or ignore logic. Its only job is "given an
// APK path, give me the raw bytes of each scannable source."
package apk

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/avast/apkparser"
)

// APK represents an opened APK file ready for source extraction.
type APK struct {
	path          string
	files         []*zip.File
	resourceTable *apkparser.ResourceTable // cached, lazy-loaded from resources.arsc
}

// Open opens the APK at path and reads its directory of contents.
// The returned APK must be closed when done.
func Open(path string) (*APK, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("apk: cannot open %s: %w", path, err)
	}
	return &APK{
		path:  path,
		files: r.File,
	}, nil
}

// Path returns the filesystem path of this APK.
func (a *APK) Path() string {
	return a.path
}

// ResourceTable parses and returns the resource table (resources.arsc) for this APK.
// The result is cached after the first successful call. Returns os.ErrNotExist if
// the APK does not contain a resources.arsc file. This is not an error—callers
// should fall back to nil resources for manifest decoding.
func (a *APK) ResourceTable() (*apkparser.ResourceTable, error) {
	if a.resourceTable != nil {
		return a.resourceTable, nil
	}
	f := a.FindFile("resources.arsc")
	if f == nil {
		return nil, os.ErrNotExist
	}
	data, err := readZipFile(f)
	if err != nil {
		return nil, fmt.Errorf("apk: cannot read resources.arsc: %w", err)
	}
	table, err := apkparser.ParseResourceTable(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("apk: cannot parse resources.arsc: %w", err)
	}
	a.resourceTable = table
	return table, nil
}

// DEXFiles reads and returns the raw bytes of every classes*.dex file
// in the APK, ordered by name (classes.dex, classes2.dex, ...).
// Returns an error if any DEX file cannot be read.
func (a *APK) DEXFiles() ([][]byte, error) {
	var dexFiles []*zip.File
	for _, f := range a.files {
		name := path.Base(f.Name)
		if strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex") {
			dexFiles = append(dexFiles, f)
		}
	}

	if len(dexFiles) == 0 {
		return nil, fmt.Errorf("apk: %s contains no DEX files", a.path)
	}

	// Sort by name so results are deterministic (classes.dex, classes2.dex, ...).
	sort.Slice(dexFiles, func(i, j int) bool {
		return dexFiles[i].Name < dexFiles[j].Name
	})

	result := make([][]byte, 0, len(dexFiles))
	for _, f := range dexFiles {
		data, err := readZipFile(f)
		if err != nil {
			return nil, fmt.Errorf("apk: cannot read %s: %w", f.Name, err)
		}
		result = append(result, data)
	}
	return result, nil
}

// Manifest reads and returns the raw bytes of AndroidManifest.xml.
// The bytes are in Android Binary XML (AXML) format and must be
// decoded by the caller before use as text.
func (a *APK) Manifest() ([]byte, error) {
	for _, f := range a.files {
		if f.Name == "AndroidManifest.xml" {
			return readZipFile(f)
		}
	}
	return nil, fmt.Errorf("apk: %s does not contain AndroidManifest.xml", a.path)
}

// DecodeManifest decodes the binary AndroidManifest.xml into plain XML text.
// The returned bytes are UTF-8 XML that can be scanned directly for secrets.
// If the APK contains a valid resources.arsc, resource ID references in the
// manifest are resolved to their string values automatically. If resources.arsc
// is missing or corrupted, resource references are left as raw hex values.
func (a *APK) DecodeManifest() ([]byte, error) {
	raw, err := a.Manifest()
	if err != nil {
		return nil, err
	}
	if table, err := a.ResourceTable(); err == nil {
		return DecodeManifestBytesWithResources(raw, table)
	}
	return DecodeManifestBytes(raw)
}

// DecodeManifestBytes decodes raw AXML bytes into plain XML text without
// resource ID resolution. Resource ID references are left as raw hex values.
// This is a standalone variant of DecodeManifest for use when the caller
// already has the manifest bytes and does not have access to resources.arsc.
func DecodeManifestBytes(raw []byte) ([]byte, error) {
	return DecodeManifestBytesWithResources(raw, nil)
}

// DecodeManifestBytesWithResources decodes raw AXML bytes into plain XML text,
// resolving resource ID references via the provided resource table. Pass nil
// for resources to leave resource ID references as raw hex values.
func DecodeManifestBytesWithResources(raw []byte, resources *apkparser.ResourceTable) ([]byte, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")

	if err := apkparser.ParseXml(bytes.NewReader(raw), enc, resources); err != nil {
		if errors.Is(err, apkparser.ErrPlainTextManifest) {
			return raw, nil
		}
		return nil, fmt.Errorf("apk: failed to decode AndroidManifest.xml: %w", err)
	}

	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("apk: failed to flush XML encoder: %w", err)
	}

	return buf.Bytes(), nil
}

// StringsXML reads and returns the raw bytes of res/values/strings.xml.
// The bytes are plain XML and can be scanned directly.
func (a *APK) StringsXML() ([]byte, error) {
	for _, f := range a.files {
		if f.Name == "res/values/strings.xml" {
			return readZipFile(f)
		}
	}
	return nil, fmt.Errorf("apk: %s does not contain res/values/strings.xml", a.path)
}

// Assets reads and returns the raw bytes of every file under assets/.
// The returned map keys are the relative paths within the APK
// (e.g. "assets/config.json"). Returns nil (not an error) when there
// are no assets.
func (a *APK) Assets() (map[string][]byte, error) {
	assets := make(map[string][]byte)
	for _, f := range a.files {
		if !strings.HasPrefix(f.Name, "assets/") {
			continue
		}
		data, err := readZipFile(f)
		if err != nil {
			return nil, fmt.Errorf("apk: cannot read %s: %w", f.Name, err)
		}
		assets[f.Name] = data
	}
	return assets, nil
}

// Close is a no-op. The zip.Reader does not hold resources that require
// explicit closing after the file data has been read.
func (a *APK) Close() error {
	return nil
}

// readZipFile reads the full contents of a zip.File entry.
func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// readZipFileRange reads len bytes starting at offset from a zip.File entry.
// This is used for DEX string table extraction to avoid loading entire files.
func readZipFileRange(f *zip.File, offset, length int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	buf := make([]byte, length)
	n, err := io.ReadFull(rc, buf)
	if err != nil {
		return nil, fmt.Errorf("apk: short read on %s: read %d of %d bytes", f.Name, n, length)
	}
	return buf, nil
}

// FindFile returns the zip.File entry for the given name, or nil if not found.
func (a *APK) FindFile(name string) *zip.File {
	for _, f := range a.files {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// ReadFileRange reads a byte range from a named file in the APK.
// This is used for DEX string table extraction to read specific sections
// without loading the entire file into memory.
func (a *APK) ReadFileRange(name string, offset, length int64) ([]byte, error) {
	f := a.FindFile(name)
	if f == nil {
		return nil, fmt.Errorf("apk: %s not found in %s", name, a.path)
	}
	return readZipFileRange(f, offset, length)
}

// DecompressedSize returns the decompressed size of a named file in the APK.
func (a *APK) DecompressedSize(name string) (uint64, error) {
	f := a.FindFile(name)
	if f == nil {
		return 0, fmt.Errorf("apk: %s not found in %s", name, a.path)
	}
	return f.UncompressedSize64, nil
}

// SourceType identifies the kind of scannable source within an APK.
type SourceType int

const (
	SourceDEX SourceType = iota
	SourceManifest
	SourceStringsXML
	SourceAsset
)

// Source is a named, typed reference to raw bytes within an APK.
type Source struct {
	Name string     // relative path within the APK (e.g. "classes.dex", "assets/config.js")
	Type SourceType // what kind of source this is
	Data []byte     // raw bytes, populated when requested
}

// String returns a human-readable label for verbose logging.
func (st SourceType) String() string {
	switch st {
	case SourceDEX:
		return "DEX"
	case SourceManifest:
		return "AndroidManifest.xml"
	case SourceStringsXML:
		return "strings.xml"
	case SourceAsset:
		return "asset"
	default:
		return "unknown"
	}
}
