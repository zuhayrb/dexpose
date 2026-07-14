package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zuhayrb/dexpose/internal/scan"
)

// Build-time variables injected by GoReleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("dexpose", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	// Flags — kept in sync with PRD §CLI Interface.
	format := fs.String("format", "table", "Output format: table (default), plain, or json")
	fs.StringVar(format, "f", "table", "Output format (shorthand)")

	outputPath := fs.String("output", "", "Write results to file instead of stdout")
	fs.StringVar(outputPath, "o", "", "Write results to file (shorthand)")

	patternsFile := fs.String("patterns", "", "Path to custom patterns file (rules.toml)")
	fs.StringVar(patternsFile, "p", "", "Path to custom patterns file (shorthand)")

	ignoreFile := fs.String("ignore", "", "Path to ignore file")
	fs.StringVar(ignoreFile, "i", "", "Path to ignore file (shorthand)")

	context := fs.Bool("context", false, "Include surrounding characters around each match")
	fs.BoolVar(context, "c", false, "Include surrounding characters (shorthand)")

	verbose := fs.Bool("verbose", false, "Print scan progress and per-file metadata")
	fs.BoolVar(verbose, "v", false, "Print scan progress (shorthand)")

	showVersion := fs.Bool("version", false, "Print version information and exit")

	quiet := fs.Bool("quiet", false, "Suppress non-fatal stderr output")
	fs.BoolVar(quiet, "q", false, "Suppress non-fatal stderr output (shorthand)")

	// Parse — ContinueOnError means we get the error back rather than os.Exit.
	if err := fs.Parse(os.Args[1:]); err != nil {
		// flag already wrote the error to stderr.
		return 2
	}

	if *showVersion {
		fmt.Fprintf(os.Stdout, "dexpose %s (%s) built %s\n", version, commit, date)
		return 0
	}

	// Validate positional argument.
	args := fs.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dexpose [flags] <path>")
		fs.Usage()
		return 2
	}
	inputPath := args[0]

	// Validate --format.
	validFormats := map[string]bool{"table": true, "plain": true, "json": true}
	if !validFormats[*format] {
		fmt.Fprintf(os.Stderr, "dexpose: unknown format %q; accepted values are table, plain, and json\n", *format)
		return 2
	}

	// Verify the input path exists and is readable before doing anything else.
	if _, err := os.Stat(inputPath); err != nil {
		fmt.Fprintf(os.Stderr, "dexpose: %v\n", err)
		return 2
	}

	// Resolve output destination.
	var outputDest io.Writer = os.Stdout
	var outputFile *os.File
	if *outputPath != "" {
		f, err := os.Create(*outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dexpose: cannot open output file: %v\n", err)
			return 2
		}
		outputFile = f
		outputDest = f
	}

	// Detect TTY for color output (only relevant for table format).
	isTTY := isTerminal(outputDest)

	cfg := scan.Config{
		Path:         inputPath,
		Format:       *format,
		OutputDest:   outputDest,
		PatternsFile: *patternsFile,
		IgnoreFile:   *ignoreFile,
		Context:      *context,
		Verbose:      *verbose,
		Quiet:        *quiet,
		Version:      version,
		IsTTY:        isTTY,
	}

	code := scan.Run(cfg)

	// Close the output file after the scan completes so the final flush
	// (especially JSON) is written before we exit.
	if outputFile != nil {
		if err := outputFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "dexpose: error closing output file: %v\n", err)
			// Don't override a findings-present exit code with 2; if Run already
			// returned 2 that takes precedence. Otherwise, a close failure is fatal.
			if code != 2 {
				code = 2
			}
		}
	}

	return code
}

// isTerminal reports whether w is a character device (i.e., a terminal).
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
	return false
}