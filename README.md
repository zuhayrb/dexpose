# dexpose

![Go Version](https://img.shields.io/badge/go-1.26%2B-blue)
![Release](https://img.shields.io/github/v/release/zuhayrb/dexpose)
![Build](https://github.com/zuhayrb/dexpose/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/zuhayrb/dexpose)

A pure-Go CLI tool that scans APK files for leaked secrets and sensitive strings. No JVM, no jadx, no runtime dependencies — just a single static binary.

## Install

```bash
go install github.com/zuhayrb/dexpose@latest
```

Or download a pre-built binary from [Releases](https://github.com/zuhayrb/dexpose/releases):

```bash
# Linux (amd64)
curl -sL https://github.com/zuhayrb/dexpose/releases/latest/download/dexpose_0.1.1_linux_amd64.tar.gz \
  | tar xz

# macOS (arm64)
curl -sL https://github.com/zuhayrb/dexpose/releases/latest/download/dexpose_0.1.1_darwin_arm64.tar.gz \
  | tar xz
```

## Usage

```bash
# Scan a single APK
dexpose target.apk

# Scan a directory of APKs, output as JSON
dexpose -f json -o results.json ./apks/

# Custom patterns + ignore file
dexpose -p my-rules.toml -i .dexposeIgnore target.apk

# Show match context and scan progress with real-time findings
dexpose --context --verbose target.apk

# Print version
dexpose --version
```

## What it scans

Within each APK, dexpose inspects:

- **DEX files** — `classes.dex`, `classes2.dex`, etc. (individual strings extracted from the DEX string table)
- **AndroidManifest.xml** — decoded from binary XML format
- **res/values/strings.xml** — plain XML scan
- **assets/** — all files scanned as plaintext

## Patterns

Ships with 59 rules covering AWS, Stripe, Slack, Twilio, SendGrid, Mailgun, Google, GitHub, Heroku, DigitalOcean, Azure, Datadog, Terraform Cloud, Shopify, Firebase, JWT tokens, high-entropy hex/base64 strings, and more. Uses [gitleaks](https://github.com/gitleaks/gitleaks)-compatible `rules.toml` format — drop in your own gitleaks config with `--patterns`.

## Ignore file

Suppress specific findings from output and exit code:

```toml
[[ignore]]
pattern = "generic-api-key"

[[ignore]]
value = "AKIAIOSFODNN7EXAMPLE"

[[ignore]]
source = "assets/vendor.bundle.js"
```

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
