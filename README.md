# dexpose

A pure-Go CLI tool that scans APK files for leaked secrets and sensitive strings. No JVM, no jadx, no runtime dependencies — just a single static binary.

## Install

```bash
go install github.com/zuhayrb/dexpose@latest
```

Or grab a pre-built binary from [Releases](https://github.com/zuhayrb/dexpose/releases).

## Usage

```bash
# Scan a single APK
dexpose target.apk

# Scan a directory of APKs, output as JSON
dexpose -f json -o results.json ./apks/

# Custom patterns + ignore file
dexpose -p my-rules.toml -i .dexposeIgnore target.apk

# Show match context and scan progress
dexpose --context --verbose target.apk
```

## What it scans

Within each APK, dexpose inspects:

- **DEX files** — `classes.dex`, `classes2.dex`, etc. (string table extraction)
- **AndroidManifest.xml** — decoded from binary XML format
- **res/values/strings.xml** — plain XML scan
- **assets/** — all files scanned as plaintext

## Patterns

Ships with a default pattern set covering AWS, Stripe, Slack, Twilio, SendGrid, Mailgun, Google, GitHub, and generic credential patterns. Uses [gitleaks](https://github.com/gitleaks/gitleaks)-compatible `rules.toml` format — drop in your own gitleaks config with `--patterns`.

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
make build     # compile
make test      # run tests with race detector
make lint      # go vet + staticcheck
make tidy      # go mod tidy + verify
```

## License

MIT
