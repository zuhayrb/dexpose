package scan

import _ "embed"

// defaultPatterns is the bundled rules.toml embedded at compile time.
// Users can override this with --patterns.
//
//go:embed patterns/rules.toml
var defaultPatterns []byte
