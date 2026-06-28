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
| 1 | Core types & CLI shell | 🔲 Not started |
| 2 | Pattern package | 🔲 Not started |
| 3 | Ignore package | 🔲 Not started |
| 4a | APK opening & source enumeration | 🔲 Not started |
| 4b | DEX string table extraction | 🔲 Not started |
| 4c | Binary XML (AXML) decoding | 🔲 Not started |
| 4d | Plain XML & asset files | 🔲 Not started |
| 5 | Scan orchestration & concurrency | 🔲 Not started |
| 6 | Output package | 🔲 Not started |
| 7 | Exit code & main.go wiring | 🔲 Not started |
| 8 | Bundled pattern set | 🔲 Not started |
| 9 | Error tolerance & edge cases | 🔲 Not started |
| 10 | Cross-platform build & release | 🔲 Not started |

---

## Directory Structure

```
dexpose/
├── main.go                          # CLI entry point (stub)
├── go.mod                           # module: github.com/zuhayrb/dexpose, go 1.22
├── go.sum                           # dependency checksums
├── Makefile                         # build / test / lint / release targets
├── .goreleaser.yaml                 # cross-platform release config
├── .github/workflows/ci.yml         # CI: test on push, release on tag
├── .gitignore
├── README.md
├── LICENSE                          # MIT
├── patterns/
│   └── rules.toml                   # bundled default patterns (stub, Phase 8)
└── internal/
    ├── apk/
    │   └── apk.go                   # stub
    ├── scan/
    │   └── scan.go                  # stub
    ├── pattern/
    │   └── pattern.go               # stub
    ├── ignore/
    │   └── ignore.go                # stub
    └── output/
        └── output.go                # stub
```

---

## Dependency Decisions

| Dependency | Version | Purpose | Decision date |
|------------|---------|---------|---------------|
| `github.com/BurntSushi/toml` | v1.3.2 | TOML parsing for rules.toml and ignore files | 2026-06-27 |
| AXML library | TBD | Binary XML decoding for AndroidManifest.xml | TBD — evaluated in Phase 4c |

All other code uses the Go standard library only. `CGO_ENABLED=0` is enforced in all build paths to guarantee fully static binaries.

---

## Key Design Decisions (from LDD)

- **No runtime dependencies** — single static binary is the core value proposition
- **Worker pool** for directory mode (`runtime.NumCPU()` workers, not user-configurable in v1)
- **Per-source goroutines** within a single APK scan (`sync.WaitGroup` coordination)
- **Output ordering** is non-deterministic in directory mode — acceptable per PRD
- **JSON output** is collected then flushed (not streamed) — consumers need complete arrays
- **Exit codes:** 0 = no findings, 1 = findings present, 2 = error — follows grep convention
- **Ignore file** suppresses both output and exit code contribution
- **Startup errors** are fatal (exit 2); per-APK/per-source runtime errors are non-fatal
- **Default patterns** embedded via `//go:embed` — zero-setup out of the box

---

## Phase 0 Notes

- Go module initialised at `github.com/zuhayrb/dexpose`, go 1.22
- `go.sum` contains BurntSushi/toml checksum placeholder; run `go mod tidy` to regenerate correctly after cloning
- GoReleaser targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 (windows/arm64 excluded)
- Build version info injected via `-ldflags`: `main.version`, `main.commit`, `main.date`
- All package stubs compile (package declarations only, no logic)
- `patterns/rules.toml` is a placeholder; real patterns written in Phase 8

---

## Open Questions

- **AXML library selection** (Phase 4c): candidates are `github.com/avast/apkparser` and `github.com/shogo82148/androidbinary`. Decision deferred until real-world APK testing in Phase 4c.
- **Context window size** (Phase 5): PRD says "a fixed number of surrounding characters" but does not specify the number. Plan: default to 40 characters on each side, not user-configurable in v1.
