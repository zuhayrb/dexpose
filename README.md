# Dexpose

![Go Version](https://img.shields.io/badge/go-1.26%2B-blue)
![Release](https://img.shields.io/github/v/release/zuhayrb/dexpose)
![Build](https://github.com/zuhayrb/dexpose/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/zuhayrb/dexpose)

A pure-Go CLI tool that scans APK files for leaked secrets and sensitive strings. No JVM, no jadx, no runtime dependencies — just a single static binary.

```
██████╗ ███████╗██╗  ██╗██████╗  ██████╗ ███████╗███████╗
██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝
██║  ██║█████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗█████╗  
██║  ██║██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║██╔══╝  
██████╔╝███████╗██╔╝ ██╗██║     ╚██████╔╝███████║███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ 

 dexpose v0.4.0 — 57 rules loaded

dexpose: scanning target.apk
dexpose: classes.dex: 14203 strings extracted
dexpose: found AKIAIOSFODNN7EXAMPLE in classes.dex [aws-access-key]
dexpose: found AIzaSyBlL7MI-FuPJ3EueRrfB2ClDXFwkwoQrSg in AndroidManifest.xml [google-api-key]
dexpose: target.apk: 2 finding(s)
dexpose: scanned 1 APK(s), 2 finding(s)
```

## Install

```bash
go install github.com/zuhayrb/dexpose@latest
```

Or download a pre-built binary from [Releases](https://github.com/zuhayrb/dexpose/releases):

```bash
# Linux (amd64)
curl -sL https://github.com/zuhayrb/dexpose/releases/latest/download/dexpose_linux_amd64.tar.gz \
  | tar xz

# macOS (arm64)
curl -sL https://github.com/zuhayrb/dexpose/releases/latest/download/dexpose_darwin_arm64.tar.gz \
  | tar xz
```

## Usage

```bash
# Scan a single APK
dexpose target.apk

# Scan a directory of APKs, output as JSON
dexpose -f json -o results.json ./apks/

# Scan with plain (tab-separated) output for piping
dexpose -f plain target.apk

# Show match context with real-time scan details
dexpose --context target.apk

# Suppress banner and progress output (quiet mode for CI)
dexpose -q target.apk

# Custom patterns + ignore file
dexpose -p my-rules.toml -i .dexposeIgnore target.apk

# Print version
dexpose --version
```

### Flags

| Flag | Shorthand | Description |
|------|-----------|-------------|
| `--format` | `-f` | Output format: `table` (default), `plain`, or `json` |
| `--output` | `-o` | Write results to file instead of stdout |
| `--patterns` | `-p` | Path to custom rules.toml |
| `--ignore` | `-i` | Path to ignore file |
| `--context` | `-c` | Include surrounding characters around each match |
| `--verbose` | `-v` | Print scan progress and per-file metadata (default: on) |
| `--color` | | Color mode: `auto` (default), `always`, or `never` |
| `--quiet` | `-q` | Suppress non-fatal stderr output (use for CI) |
| `--version` | | Print version information and exit |

### Output formats

**Table** (default) — styled table with colored severity indicators:

```
SEVERITY  TYPE               LOCATION            MATCH
HIGH      aws-access-key     classes.dex         AKIAIOSFODNN7EXAMPLE
HIGH      google-api-key     AndroidManifest.xml AIzaSyBlL7MI-FuPJ3EueRrfB2ClDXFwkwoQrSg
HIGH      jwt-token          assets/config.json  eyJhbGciOiJIUzI1NiJ9...
```

Colors are automatically enabled when output goes to a terminal and
disabled when piped. Use `--color=always` to force colors on (e.g. in
a terminal that doesn't report itself as a TTY), or `--color=never`
to suppress them. The `NO_COLOR` environment variable also disables
colors. Use `-f plain` for machine-parseable output.

**Plain** — tab-separated lines (pipe-friendly):

```
target.apk  classes.dex              aws-access-key    AKIAIOSFODNN7EXAMPLE
target.apk  AndroidManifest.xml      google-api-key    AIzaSyBlL7MI-FuPJ3EueRrfB2ClDXFwkwoQrSg
target.apk  assets/config.json       jwt-token         eyJhbGciOiJIUzI1NiJ9...
```

**JSON** — structured array, pipeable into jq:

```bash
dexpose -f json target.apk | jq '.[].pattern'
```

```json
[
  { "apk": "target.apk", "source": "classes.dex", "pattern": "aws-access-key", "match": "AKIAIOSFODNN7EXAMPLE" },
  { "apk": "target.apk", "source": "AndroidManifest.xml", "pattern": "google-api-key", "match": "AIzaSyBlL7MI-FuPJ3EueRrfB2ClDXFwkwoQrSg" }
]
```

### CI usage

By default dexpose shows a banner, scan progress, and per-file details. For CI
pipelines, pass `--quiet` (`-q`) to suppress everything but findings:

```bash
dexpose -f json -o results.json -q ./release.apk && echo "clean" || echo "secrets found"
```

Exit code 1 when findings exist, 0 when clean.

### Ignoring false positives

Create a `.dexposeIgnore` file:

```toml
[[ignore]]
pattern = "generic-api-key"

[[ignore]]
value = "AKIAIOSFODNN7EXAMPLE"

[[ignore]]
source = "assets/vendor.bundle.js"
```

Suppressed findings are excluded from both output and exit code.

## What it scans

Within each APK, dexpose inspects:

- **DEX files** — `classes.dex`, `classes2.dex`, etc. (individual strings extracted from the DEX string table)
- **AndroidManifest.xml** — decoded from binary XML format; resource ID references (e.g. `@0x7F010000`) are resolved to their string values via `resources.arsc` when available
- **res/values/strings.xml** — plain XML scan (present in debug APKs)
- **resources.arsc** — compiled binary resource table scanned for string-type entries (present in all APKs; is the primary source of string values in release APKs where `strings.xml` is stripped)
- **assets/** — all files scanned as plaintext

## Patterns

Ships with 57 rules covering AWS, Stripe, Slack, Twilio, SendGrid, Mailgun, Google, GitHub, Heroku, DigitalOcean, Azure, Datadog, Terraform Cloud, Shopify, Firebase, JWT tokens, and more. Uses [gitleaks](https://github.com/gitleaks/gitleaks)-compatible `rules.toml` format — drop in your own gitleaks config with `--patterns`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | One or more findings present |
| 2 | Scan error |

## Development

```bash
make build     # sync patterns + compile
make test      # run tests with race detector
make lint      # go vet + staticcheck
make tidy      # go mod tidy + verify
make snapshot  # local GoReleaser dry run
make sync      # copy patterns for go:embed
```

## Security

Verify downloaded binaries against the SHA-256 checksums published with each release:

```bash
sha256sum dexpose
cat checksums.txt
```

## Support ☕

If you find dexpose useful, consider supporting development:

- **BTC**: `bc1qarlskqtdq4wsdudecktv6g7zqv5jv52at9k5uk`
- **ETH/ERC-20**: `0x03d42691a1f0d9af62899813e1f3937da0f6039b`
- **SOL/SLP**: `J9jneBCAW8NaoSj5KekxLyxBcYbzNq3F2Wshdar7FHdf`

## License

MIT License — see [LICENSE](LICENSE) for details.
