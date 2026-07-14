// Package output provides ANSI color helpers for terminal output.
package output

// ANSI color codes
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Gray   = "\033[90m"
)

// colorize wraps text with ANSI color codes if TTY is attached.
func colorize(text, color string, isTTY bool) string {
	if !isTTY {
		return text
	}
	return color + text + Reset
}

// bold wraps text in bold ANSI code.
func bold(text string) string {
	return Bold + text + Reset
}

// red wraps text in red ANSI code.
func red(text string) string {
	return Red + text + Reset
}

// yellow wraps text in yellow ANSI code.
func yellow(text string) string {
	return Yellow + text + Reset
}

// dim wraps text in dim ANSI code.
func dim(text string) string {
	return Dim + text + Reset
}

// severityColor returns the color for a given severity level.
func severityColor(severity string) string {
	switch severity {
	case "HIGH":
		return Red
	case "MEDIUM":
		return Yellow
	default:
		return Dim
	}
}

// Styled checkmark for scanned files.
func Checkmark(isTTY bool) string {
	return colorize("✓", Green, isTTY)
}

// Styled "SCANNED" label.
func ScannedLabel(isTTY bool) string {
	return colorize("SCANNED", Cyan, isTTY)
}

// Styled severity badge.
func severityBadge(severity string, isTTY bool) string {
	color := severityColor(severity)
	return colorize(severity, color, isTTY)
}

// Styled shield icon for completion.
func ShieldIcon(isTTY bool) string {
	return colorize("🛡", Green, isTTY)
}