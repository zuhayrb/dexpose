# dexpose — Implementation Memory

**Project:** `github.com/zuhayrb/dexpose`
**Author:** Zuhayr Barhoumi
**Started:** 2026-06-27
**Reference docs:** dexpose-prd.md, dexpose-ldd.md, dexpose-ppd.md

---

## Phase Status

| Phase | Name | Status |
|-------|------|--------|
| 0 | Project scaffold | ✅ Complete |
| 1 | Core types & CLI shell | ✅ Complete |
| 2 | Pattern package | ✅ Complete |
| 3 | Ignore package | ✅ Complete |
| 4a | APK opening & source enumeration | ✅ Complete |
| 4b | DEX string table extraction | ✅ Complete |
| 4c | Binary XML (AXML) decoding | ✅ Complete |
| 4d | Plain XML & asset files | ✅ Complete |
| 4e | Compiled resource string scanning (resources.arsc) | ✅ Complete |
| 5 | Scan orchestration & concurrency | ✅ Complete |
| 6 | Output package | ✅ Complete |
| 7 | Exit code & main.go wiring | ✅ Complete |
| 8 | Bundled pattern set | ✅ Complete |
| 9 | Error tolerance & edge cases | ✅ Complete |
| 10a | Release: `make snapshot` to verify GoReleaser builds | ✅ Complete |
| 10b | Release: tag v0.1.0 and push to trigger CI release | ✅ Complete |
| 10c | Release: verify GitHub Releases page has all 5 binaries + checksums | ✅ Complete |
| 10d | Release: update README with badges, support section, FUNDING.yml | ✅ Complete |
| 10e | Release: set up Homebrew tap (optional, low priority) | 🔲 Not started |

---

## Premium Pattern Pack (separate product)

A standalone `premium.toml` (~150 rules) sold on Gumroad as a one-time purchase ($49).
Not part of the dexpose OSS project. Located in `premium/` (gitignored).

- `premium.toml` — the product, gitleaks-compatible format (60 rules so far)
- `sandbox/validate.go` — pattern validation harness (complete, 60 rules pass)
- `sandbox/fixtures/` — known-good, known-bad, edge-case credential samples (34 fixtures)
- `sandbox/harvesters/` — scripts for discovering new key format announcements
- `sandbox/generators/` — scripts for generating synthetic test keys

Plan document: `docs/dexpose-patterns-pack-plan.md`
Session memory: `premium/memory.md`

**Dexpose support:** `pattern.Rule` and `model.Finding` now carry a `Premium bool` field. When a premium pattern fires, output includes `[PREMIUM]` (plain) or `"premium": true` (JSON). This is the visibility signal — users see what the pack finds that free patterns miss.

**2026-07-10 session:** First batch of 50 patterns written and validated. Validator complete. Dexpose Premium plumbing deployed. See `premium/memory.md` for full details.

**2026-07-11 session:** AWS, Stripe, GitHub premium patterns added (10 new rules, 50→60 total). All validated and end-to-end tested with `[PREMIUM]` tag.

**2026-07-12 session:** Audited all premium rules against free pack — removed 11 duplicates (firebase, azure, datadog, supabase, stripe, mongodb, redis overlap). Added 10 genuinely new patterns for GitLab, Discord, Asana, Atlassian, Telegram, Intercom, Zendesk. Net: 60→59 rules, all non-overlapping with free coverage.

---

## Directory Structure

```
dexpose/
├── premium/                             # Separate product — premium pattern pack (gitignored)
│   ├── premium.toml                     # ~150 rules, sold on Gumroad
│   ├── README.md                        # Product docs & purchase link
│   └── sandbox/                         # Pattern validation pipeline
│       ├── fixtures/                    # known-good, known-bad, edge-cases
│       ├── harvesters/                  # Changelog monitors, format discovery
│       ├── generators/                  # Synthetic key generators
│       └── validate.go                  # Validation harness
├── main.go                              # CLI entry point, flag parsing, exit code
├── go.mod                               # module: github.com/zuhayrb/dexpose, go 1.26.4
├── go.sum                               # dependency checksums
├── Makefile                             # build / test / lint / release / sync targets
├── .goreleaser.yaml                     # cross-platform release config
├── .github/
│   ├── workflows/ci.yml             # CI: test on push, release on tag
│   └── FUNDING.yml                  # crypto wallet links for Sponsor sidebar
├── .gitignore
├── README.md                            # ✅ added
├── LICENSE                              # MIT ✅ added
├── patterns/
│   └── rules.toml                       # 54 rules: AWS, Stripe, Slack, Twilio, SendGrid,
│                                        # Mailgun, Google, GitHub, Heroku, DigitalOcean,
│                                        # Datadog, New Relic, PagerDuty, npm, PyPI,
│                                        # Confluent, Doppler, Terraform, Vault, Azure,
│                                        # Shopify, Twitch, generic heuristics, connection strings
└── internal/
    ├── apk/
    │   ├── apk.go                       # ✅ APK opening, source enumeration, AXML decoding, ResourceStrings()
    │   ├── dex.go                       # ✅ DEX string table extraction (ULEB128/MUTF-8)
    │   ├── apk_test.go                  # ✅ 24 tests (+3 ResourceStrings tests)
    │   ├── apk_edge_test.go             # ✅ 20 tests (error tolerance)
    │   ├── dex_test.go                  # ✅ 12 tests
    │   └── testdata/
    │       ├── AndroidManifest.axml     # real AXML binary for testing
    │       ├── resources.arsc           # minimal resource table for testing
    │       └── resources_arsc_strings.arsc  # fixture with 2 string entries for testing
    ├── scan/
    │   ├── scan.go                      # ✅ orchestration, worker pool, finding collection, resources.arsc scanning
    │   ├── scan_test.go                 # ✅ 13 tests (integration, error tolerance, resources.arsc)
    │   ├── embed.go                     # ✅ go:embed for bundled patterns
    │   └── patterns/
    │       └── rules.toml               # copy of patterns/rules.toml (for go:embed)
    ├── pattern/
    │   ├── pattern.go                   # ✅ complete
    │   └── pattern_test.go              # ✅ 28 tests (incl. smoke tests for new rules)
    ├── ignore/
    │   ├── ignore.go                    # ✅ complete
    │   └── ignore_test.go               # ✅ 23 tests
    ├── model/
    │   └── finding.go                   # ✅ shared Finding type (breaks scan↔ignore cycle)
    └── output/
        ├── output.go                    # ✅ plain + JSON formatters
        └── output_test.go               # ✅ 11 tests
```

---

## Dependency Decisions

| Dependency | Version | Purpose | Decision date |
|------------|---------|---------|---------------|
| `github.com/BurntSushi/toml` | v1.6.0 | TOML parsing for rules.toml and ignore files | 2026-06-27 |
| `github.com/avast/apkparser` | v0.0.0-20260423 | Binary XML (AXML) decoding for AndroidManifest.xml | 2026-07-02 |
| `github.com/klauspost/compress` | v1.18.0 | Transitive dependency of apkparser | 2026-07-02 |

All other code uses the Go standard library only. `CGO_ENABLED=0` is enforced in all build paths to guarantee fully static binaries.

**2026-07-14:** `golang.org/x/term` and `golang.org/x/sys` removed as dependencies.
TTY detection now uses `os.ModeCharDevice` from the standard library — zero
external deps remain beyond the two listed above.

---

## Key Design Decisions (from LDD)

- **No runtime dependencies** — single static binary is the core value proposition
- **Worker pool** for directory mode (`runtime.NumCPU()` workers, not user-configurable in v1)
- **Per-source goroutines** within a single APK scan — replaced with sequential source scanning within a single APK (simpler, no measurable perf difference for typical APKs)
- **Output ordering** is non-deterministic in directory mode — acceptable per PRD
- **JSON output** is collected then flushed (not streamed) — consumers need complete arrays
- **Exit codes:** 0 = no findings, 1 = findings present, 2 = error — follows grep convention
- **Ignore file** suppresses both output and exit code contribution
- **Startup errors** are fatal (exit 2); per-APK/per-source runtime errors are non-fatal
- **Default patterns** embedded via `//go:embed` — zero-setup out of the box
- **Context window:** 40 characters on each side of match, not user-configurable in v1
- **Import cycle resolution:** `Finding` type lives in `internal/model` to break scan↔ignore cycle

---

## Phase 0 Notes

- Go module initialised at `github.com/zuhayrb/dexpose`, go 1.26.4
- GoReleaser targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 (windows/arm64 excluded)
- Build version info injected via `-ldflags`: `main.version`, `main.commit`, `main.date`

---

## Phase 2 Notes

**Files produced:**
- `internal/pattern/pattern.go` — full implementation
- `internal/pattern/pattern_test.go` — 15 tests
- `patterns/rules.toml` — 27 rules (replaces stub)

**API surface:**
- `Load(data []byte) (*Matcher, error)` — parses TOML, compiles all regexes; fatal on invalid regex, empty rule set, missing id, or empty regex
- `Matcher.Match(s string) []Match` — returns one `Match` per firing rule; uses `FindString` (first hit per rule only)
- `Matcher.RuleCount() int` — for `--verbose` startup logging
- `Match` struct: `RuleID string`, `Value string` (the regex-matched substring)

---

## Phase 3 Notes

**Files produced:**
- `internal/ignore/ignore.go` — full implementation
- `internal/ignore/ignore_test.go` — 23 tests

**API surface:**
- `Load(data []byte) (*List, error)` — parses TOML; fatal on invalid TOML or any `[[ignore]]` entry that sets none of pattern/value/source.
- `List.Suppressed(f model.Finding) bool` — true if any entry matches; increments the suppression counter on a match. **Nil-safe**: a nil `*List` always returns `false`.
- `List.SuppressedCount() int` — for the `--verbose` summary line. Nil-safe, returns `0`.
- `List.EntryCount() int` — number of loaded entries. Nil-safe, returns `0`.

**Design decision — multi-field entry semantics:**
AND within an entry, OR across entries. A multi-field entry only suppresses a finding that matches every field it sets; a `List` suppresses a finding if any entry matches.

---

## Phase 4 Notes

### Phase 4a — APK opening & source enumeration

**Files produced:**
- `internal/apk/apk.go` — APK struct, Open, DEXFiles, Manifest, StringsXML, Assets, DecodeManifest, ResourceStrings
- `internal/apk/apk_test.go` — 15 tests

**API surface:**
- `Open(path string) (*APK, error)` — opens ZIP, reads directory
- `(*APK) DEXFiles() ([][]byte, error)` — sorted classes*.dex files
- `(*APK) Manifest() ([]byte, error)` — raw AXML bytes
- `(*APK) ResourceTable() (*apkparser.ResourceTable, error)` — resources.arsc parser, lazy-loaded, cached
- `(*APK) ResourceStrings() (map[string]string, error)` — extracts all string-type entries from resources.arsc (key → value); returns os.ErrNotExist if missing
- `(*APK) DecodeManifest() ([]byte, error)` — decoded plain XML (uses resource table if available)
- `(*APK) StringsXML() ([]byte, error)` — plain XML bytes
- `(*APK) Assets() (map[string][]byte, error)` — all assets/ files
- `DecodeManifestBytes(raw []byte) ([]byte, error)` — standalone AXML decode (no resource resolution)
- `DecodeManifestBytesWithResources(raw []byte, resources *apkparser.ResourceTable) ([]byte, error)` — standalone AXML decode with resource ID resolution

### Phase 4b — DEX string table extraction

**Files produced:**
- `internal/apk/dex.go` — ExtractStrings, validateDEXHeader, readMUTF8String, readULEB128
- `internal/apk/dex_test.go` — 12 tests (hand-crafted DEX binaries)

**Design notes:**
- Native Go implementation, no external dependencies
- Reads string_ids section + string_data section from DEX header
- ULEB128 length prefix + raw bytes (MUTF-8 treated as ASCII for secrets scanning)
- Validates magic number, header bounds, string offsets

### Phase 4c — Binary XML decoding

**Decision:** `github.com/avast/apkparser` selected over `shogo82148/androidbinary`
- More recently maintained (April 2026)
- Cleaner API: `ParseXml(reader, encoder, resources)` with nil resources support
- Handles ErrPlainTextManifest gracefully
- Transitive dependency: `klauspost/compress` (pure Go, widely used)

**Integration:**
- `apk.DecodeManifest()` wraps `apkparser.ParseXml` with XML encoder output
- `apk.DecodeManifestBytes()` is a standalone variant for pre-extracted bytes
- Resource references left as hex when resources.arsc is absent (acceptable for secrets scanning)

**2026-07-05: Resource ID resolution added:**
- `APK.ResourceTable()` lazy-loads and caches `resources.arsc` via `apkparser.ParseResourceTable`
- `DecodeManifest()` now passes the resource table to `ParseXml` when available
- `DecodeManifestBytesWithResources()` exposed for standalone callers that have a resource table
- Fallback: missing or corrupted `resources.arsc` silently degrades to nil resources (preserving existing behavior)
- Test fixture: minimal 12-byte `testdata/resources.arsc` with 0 packages (valid, parses cleanly)

### Phase 4d — Plain XML & asset files

- `StringsXML()` returns raw XML bytes for direct scanning
- `Assets()` returns `map[string][]byte` for all files under `assets/`
- No additional processing needed — plaintext sources are scanned as-is

---

## Phase 5 Notes

**Files produced:**
- `internal/scan/scan.go` — full orchestration (Run, scanAPK, scanAPKPool, scanContent, extractContext)
- `internal/scan/embed.go` — go:embed for bundled patterns

**API surface:**
- `Run(cfg Config) int` — entry point; loads patterns/ignore, collects APKs, scans, applies ignore, writes output, returns exit code

**Concurrency model:**
- Worker pool: `runtime.NumCPU()` workers for directory mode (capped at number of APKs)
- Single APK: no goroutine overhead, sequential scan
- Per-source scanning is sequential within each APK (simpler, sufficient for v1)

**Key functions:**
- `scanAPK(apkPath, matcher, cfg)` — opens APK, scans all sources (DEX strings, manifest, strings.xml/resources.arsc, assets), returns findings
- `scanAPKPool(apkPaths, matcher, cfg)` — fan-out/fan-in worker pool
- `scanContent(apkPath, sourceName, content, matcher, cfg)` — runs all rules against a string
- `extractContext(content, value)` — 40-char window around match

**Pattern loading:**
- `//go:embed` from `internal/scan/patterns/rules.toml` (copied from `patterns/rules.toml` via `make sync`)

---

## Phase 6 Notes

**Files produced:**
- `internal/output/output.go` — Write, writePlain, writeJSON, writeTable, headerRow, severityCell, truncate
- `internal/output/color.go` — ANSI helpers (bold, red, yellow, dim, green, cyan, blue, gray), Checkmark, ScannedLabel, ShieldIcon
- `internal/output/severity.go` — SeverityFromPattern, severityColor, severityBadge
- `internal/output/output_test.go` — 11+ tests

**API surface:**
- `Write(findings []model.Finding, format string, w io.Writer, isTTY bool) error` — routes to writeTable/writePlain/writeJSON based on format. `isTTY=true` enables ANSI color codes in table output.
- `writeTable()` — column-aligned headers + rows with colored severity badges
- `writePlain()` — tab-separated lines (apk, source, pattern, match, [context], [PREMIUM])
- `writeJSON()` — collected array with `omitempty` on context field
- `SeverityFromPattern(id string) string` — maps rule ID prefix to HIGH/MEDIUM/LOW
- `Checkmark(isTTY bool) string` — green `✓` when isTTY
- `ShieldIcon(isTTY bool) string` — green `🛡` when isTTY
- `ScannedLabel(isTTY bool) string` — cyan `SCANNED` when isTTY

---

## Phase 7 Notes

- `main.go` was already wired from Phase 1; `scan.Run` now does real work
- Exit code logic: Run returns 0/1/2, main.go passes through os.Exit
- All flags: --format, --output, --patterns, --ignore, --context, --verbose (default: on), --quiet, --color, --version
- `--verbose` default changed to `true` in v0.4.1 — `-q` now acts as "non-verbose"
- `--color` flag (auto/always/never) added in v0.4.1 for explicit color control
- TTY detection via `isTerminal()` (stdlib `os.ModeCharDevice`, no external deps)

---

## Phase 9 Notes

**Files produced:**
- `internal/apk/apk_edge_test.go` — 20 tests: corrupted APKs, malformed DEX/AXML, large/unicode content, concurrent access, directory edge cases
- `internal/scan/scan_test.go` — 11 tests: integration tests for scan pipeline, error tolerance, ignore suppression, JSON output, context extraction

**Key fix — per-APK error tolerance:**
- `scanAPKPool` previously returned `firstErr`, causing `Run` to exit 2 on any single APK failure
- Fixed: pool now warns to stderr and skips bad APKs, continuing with remaining APKs
- Per-APK errors are non-fatal; only startup errors (missing patterns file, bad ignore file) are fatal

---

## Phase 8 Notes

**Files produced:**
- `patterns/rules.toml` — expanded from 27 to 54 rules
- `internal/pattern/pattern_test.go` — 13 new smoke tests for new rules

**New rule categories added:**
- Cloud/DevOps: Heroku API key, DigitalOcean token, Datadog API/app key, New Relic key, PagerDuty integration key
- Package registries: npm token, PyPI token
- Streaming/infra: Confluent API key, Doppler token, Terraform Cloud token, HashiCorp Vault token
- Platform: Azure storage/account keys, Shopify access token, Twitch client secret
- Connection strings: PostgreSQL, MySQL, MongoDB URIs
- Generic: base64-encoded high-entropy blocks (16+ chars)

---

## Architecture: Import Graph

```
main → scan → apk
           → pattern
           → ignore → model
           → output → model
           → model
```

`model.Finding` breaks the scan↔ignore cycle. No package imports `scan`.

---

## End-to-End Verification

Tested with synthetic APK containing:
- DEX file with AWS access key → ✅ detected
- AndroidManifest.xml with Stripe secret key → ✅ detected (decoded from plain XML test)
- assets/config.json with Google API key + GitHub PAT → ✅ detected
- res/values/strings.xml with password assignment → ✅ detected
- Ignore file suppressing aws-access-key → ✅ suppressed, exit code correct
- JSON output with --context → ✅ valid JSON with context field
- Exit codes: 0 (no findings), 1 (findings), 2 (error) → ✅ all correct

---

## Remaining Tasks

### Phase 8 — Bundled pattern set ✅
- Expanded `patterns/rules.toml` from 27 to 54 rules (Heroku, DigitalOcean, Datadog, New Relic, npm, PyPI, Confluent, Doppler, Terraform, Vault, Azure, Shopify, Twitch, connection strings)
- 13 new smoke tests added to `pattern_test.go`
- `make sync` keeps `internal/scan/patterns/rules.toml` in sync

### Phase 9 — Error tolerance & edge cases ✅
- Corrupted APK tests: truncated ZIP, empty file, random bytes, bad CRC
- Malformed DEX tests: short header, bad magic, corrupt string table offset, zero strings
- Malformed AXML tests: random bytes, empty, truncated
- Source enumeration tests: no DEX, missing manifest, missing strings.xml, empty assets
- Large/unicode content tests: 500-string DEX, Latin-1/UTF-8 content
- Concurrent access test: 10 goroutines calling DEXFiles simultaneously
- Per-APK error tolerance fix: `scanAPKPool` now warns and skips bad APKs instead of returning fatal error
- 11 scan integration tests covering: single APK, missing patterns, missing ignore, nonexistent path, empty directory, non-APK files, corrupted APK skipping, ignore suppression, JSON format, context extraction, multi-APK directory mode

### Phase 10a — GoReleaser snapshot
```bash
make snapshot
```
Verify all 5 targets build: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64.

### Phase 10b — Tag and release
```bash
make release TAG=v0.1.0
```
Pushes tag, CI runs tests then GoReleaser publishes to GitHub Releases.

### Phase 10c — Verify release
- Check `https://github.com/zuhayrb/dexpose/releases` has all 5 archives
- Verify `checksums.txt` is present
- Download one archive and confirm binary works

### Phase 10d — README & repo polish ✅
- Added badges: Go Version, Release, Build, License
- Added Support section with BTC/ETH/SOL addresses
- Created `.github/FUNDING.yml` for Sponsor sidebar
- Fixed LICENSE link in README
- Set repo description and topics via `gh repo edit`

### Phase 10e — Homebrew tap (optional)
- Create `zuhayrb/homebrew-tap` repo with formula pointing to release archives
- GoReleaser can automate this with a brew tap in `.goreleaser.yaml`

## Unresolved Design Issues (from critique.md)

These are acknowledged design tensions not yet addressed:

1. ~~**FindString → FindAllString** — Currently uses `FindString` (first match per rule per string). A string containing three distinct AWS keys reports only one. `FindAllString` would align with the over-reporting philosophy but requires deduplication logic.~~ ✅ **Resolved in v0.1.1** — switched to `FindAllString` with per-match dedup.

2. **Non-deterministic output ordering** — No sort step before output. CI baselining requires diffable output. A `--sort` flag or post-collection sort would fix this.

3. ~~**resources.arsc not scanned** — Release APKs strip `res/values/strings.xml` and compile string resources into the binary resource table. Dexpose was missing this primary string source.~~ ✅ **Resolved in v0.4.0** — `APK.ResourceStrings()` extracts string-type entries from `resources.arsc`, and `scanAPK()` scans them when `strings.xml` is absent.

---

## v0.2.0 Changes (2026-07-04)

### Features

1. **`-v` shorthand for `--verbose`** (`main.go:43-44`) — `dexpose -v target.apk` enables verbose mode. Changed from `--version` shorthand per user feedback — `-v` for verbose is the universal convention.

2. **`-c` shorthand for `--context`** (`main.go:40-41`) — `dexpose -c target.apk` enables context output.

3. **`--quiet` / `-q` flag** (`main.go:45-46`, `scan.go:46`) — Suppresses non-fatal stderr output (per-APK scan warnings), keeping output clean for scripting. Fatal errors (missing patterns, bad path) are still shown.

4. **Flags table in README** — New reference table documents all flags, shorthands, and descriptions.

---

## v0.4.1 Terminal Output & Verbose Changes (2026-07-14)

### Table output format (replaces plain as default)

**Default format changed from `plain` to `table`** (`main.go:28-29`). Table format
provides a styled, column-aligned view with colored severity badges. Plain format
is still available via `-f plain` for piping.

**Files created:**
- `internal/output/color.go` — ANSI color constants (`Red`, `Green`, `Cyan`, `Yellow`, `Dim`, `Bold`, `Reset`) and helper functions (`bold()`, `red()`, `yellow()`, `dim()`, `colorize()`, `Checkmark()`, `ScannedLabel()`, `ShieldIcon()`, `severityBadge()`)
- `internal/output/severity.go` — `SeverityFromPattern(patternID) string` maps pattern ID prefixes (e.g. `aws-` → `HIGH`, `generic-` → `MEDIUM`, `private-key-` → `HIGH`) to severity levels. All 57 rules classified.

**Files modified:**
- `internal/output/output.go` — Added `writeTable()`, `headerRow()`, `severityCell()`, `truncate()`. Updated `Write()` signature to `Write(findings, format, w, isTTY bool)`.
- `internal/scan/scan.go` — Added `Config.IsTTY bool`, `printProgress()` for per-file status lines (`✓ classes.dex SCANNED`), summary output after scan completion.
- `main.go` — Default format `"table"`, TTY detection via `os.ModeCharDevice`.
- `README.md` — Updated with table format docs, flags, and examples.

### TTY detection: removed golang.org/x/term dependency

`golang.org/x/term.IsTerminal()` was returning false in some terminal
configurations. Replaced with a standard library `isTerminal()` helper using
`os.Stat().Mode()&os.ModeCharDevice` on the output destination. (`main.go:130-137`)

- Removed `golang.org/x/term` and transitive `golang.org/x/sys` from `go.mod`
- Zero external dependencies for TTY detection

### `--color` flag added

New flag: `--color=auto|always|never` (`main.go:46`). Resolution order:

1. `--color=always` → force ANSI codes on
2. `--color=never` → force ANSI codes off
3. `--color=auto` (default) → check `NO_COLOR` env var, then TTY detection

Provides an explicit override when auto-detection fails. Respects the
`NO_COLOR` environment variable per https://no-color.org/.

### `--verbose` now default on, `-q` is "non-verbose"

**Change:** `--verbose` default flipped from `false` to `true` (`main.go:43-44`).

**Rationale:** Users see the banner, scan activity, and findings immediately
without needing a flag. The tool felt silent on first run.

**CI impact:** All 12 `if cfg.Verbose {` gates in `scan.go` changed to
`if cfg.Verbose && !cfg.Quiet {`. The existing `-q` / `--quiet` flag now
suppresses banner, all scan messages, per-finding stderr output, and the
verbose summary. CI usage: `dexpose -f plain -q app.apk`.

### Infrastructure

- `.goreleaser` → `.goreleaser.yaml` renamed for GoReleaser v2 compatibility.
  Archive `name_template` drops `{{ .Version }}` so release URLs are
  version-agnostic (`dexpose_linux_amd64.tar.gz`).

---

## v0.4.0 Changes (2026-07-09)

### Features

1. **`resources.arsc` string resource scanning** (`internal/apk/apk.go:163-244`, `internal/scan/scan.go:306-333`) — `APK.ResourceStrings()` extracts all string-type resource entries from the binary resource table by iterating all package IDs (0x01–0x7f), type IDs (1–254), and entry indices (0–65535). Returns a `map[string]string` of resource key → string value.

2. **`extractResourceStrings()` helper** (`internal/apk/apk.go:184-244`) — Probe loop for discovering string types: iterates the first 10 entries per type; if the first non-errored entry has `ResourceType == "string"`, scans all entries for string values. Keys are sorted for deterministic output.

3. **Release APK scanning in `scanAPK()`** (`internal/scan/scan.go:306-333`) — When `strings.xml` is absent (release APK), `resources.arsc` is scanned. Findings are tagged as `source: "resources.arsc"`. When `strings.xml` is present (debug APK), `resources.arsc` is skipped to avoid duplicate findings.

### Test fixtures

- **`testdata/resources_arsc_strings.arsc`** (644 bytes) — Hand-crafted binary resource table via Go builder (`encoding/binary`), containing 2 string entries (`aws_key=AKIAIOSFODNN7EXAMPLE`, `label=not_a_secret`). Built using exact byte-level layout matching `avast/apkparser` expectations: string pools (UTF-16LE), type spec chunk, type chunk with entry offset array and simple entries.

### Tests

- `TestResourceStrings_Present` — happy path, verifies key/value extraction
- `TestResourceStrings_NoARSC` — returns error when resources.arsc missing
- `TestResourceStrings_CorruptedARSC` — returns error when corrupted
- `TestRun_ResourcesARSC_FindsSecrets` — integration test: release APK with resources.arsc, no strings.xml → finds AWS key
- `TestRun_ResourcesARSC_SkippedWhenStringsXMLPresent` — debug APK with both → skips resources.arsc

---

## v0.3.0 Changes (2026-07-05)

### Features

1. **`resources.arsc` resource ID resolution** (`internal/apk/apk.go:49-71, 122-161`) — `APK.ResourceTable()` lazy-loads and caches `resources.arsc` via `apkparser.ParseResourceTable`. `DecodeManifest()` now passes the resource table to `ParseXml` when available, resolving resource ID references (e.g. `@0x7F010000`) to their string values. Falls back gracefully to nil resources when arsc is missing or corrupted. Test fixture: minimal 12-byte `testdata/resources.arsc`.

2. **`DecodeManifestBytesWithResources()`** (`internal/apk/apk.go:141-161`) — standalone variant for callers that already have a resource table. `DecodeManifestBytes()` now delegates to `DecodeManifestBytesWithResources(raw, nil)`.

3. **6 new tests** in `apk_test.go` — `TestResourceTable_Present`, `TestResourceTable_Missing`, `TestResourceTable_Corrupted`, `TestDecodeManifest_WithResources_NoARSC`, `TestDecodeManifest_WithResources_ARSC`, `TestDecodeManifest_WithResources_Fallback`.

### Fixes

1. **DEX magic validation too strict** (`internal/apk/dex.go:9, 50-57`) — Previously only accepted `dex\n039\0` (Android 10+). Changed to check only the first 4 bytes (`dex\n`) and that byte 7 is `\0`, accepting all DEX versions (035–039). This eliminates false "invalid DEX magic" warnings on older APKs.

2. **`-v` flag reassigned to `--verbose`** (`main.go:43-46`) — Changed from `--version` shorthand to `--verbose` shorthand, matching Unix convention (`curl -v`, `gcc -v`, `ssh -v`). `--version` now has no shorthand.

### Docs

- `docs/dexpose-verify-ppd.md` — Product proposal for a companion verification tool
- `docs/dexpose-patterns-pack-plan.md` — Product plan for premium pattern pack tiers, sandbox validation pipeline, and monetization
- README updated: banner version, download URLs, flag table, usage examples, ARSC resolution note

---

### Fixes

1. **README download URLs updated** — Point to `v0.1.5` archives instead of stale `v0.1.2` references.

---

## v0.1.1 Changes (2026-07-04)

### Fixes

1. **DEX scanning now uses `ExtractStrings()`** (`scan.go:252-278`) — Instead of running regexes against the raw DEX binary (headers, tables, etc.), the pipeline now extracts individual strings from the DEX string table via `apk.ExtractStrings()` and scans each string independently. This makes assignment-pattern rules (`generic-api-key`, `generic-secret`, etc.) actually work on DEX strings, since credentials are stored as standalone values in the string table. Falls back to raw binary scanning if DEX extraction fails.

2. **PEM regexes now capture full blocks** (`patterns/rules.toml`) — `private-key-pem` and `google-service-account-key` were matching only the `-----BEGIN PRIVATE KEY-----` header line. Now they match the entire PEM block (header + base64 content + footer), so the actual key value is captured as the match.

3. **FindString → FindAllString** (`pattern.go:99-113`) — Each rule now returns all distinct matches within a string, not just the first. Duplicate values are deduplicated to avoid noise.

### New patterns added (59 total, +5)

| Rule | Regex |
|------|-------|
| `google-oauth-client-id` | `[0-9]{10,}-[a-zA-Z0-9_]+\.apps\.googleusercontent\.com` |
| `firebase-url` | `[a-zA-Z0-9_-]+\.firebaseio\.com` |
| `jwt-token` | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| `high-entropy-hex` | `[0-9a-fA-F]{32,64}` |
| `high-entropy-base64` | `[A-Za-z0-9+/]{40,}={0,2}` |

### Verbose mode improvements

`--verbose` now prints each finding to stderr as it's discovered (with 80-char preview), plus string counts per DEX file. Previously it only showed a final count line. (`scan.go:336-341`)

---

## Unreleased

