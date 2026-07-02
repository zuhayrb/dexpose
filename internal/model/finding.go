// Package model defines the shared data types used across the dexpose
// pipeline. Extracting Finding here breaks the import cycle between
// scan and ignore.
package model

// Finding is the core data structure produced by a scan and consumed by
// the output and ignore packages. No package mutates a Finding after creation.
type Finding struct {
	APK     string // path to the APK file on disk
	Source  string // source file within the APK (e.g. "classes.dex", "assets/config.js")
	Pattern string // name of the matched pattern rule
	Match   string // the matched string value
	Context string // surrounding characters; populated only when Config.Context is true
}
