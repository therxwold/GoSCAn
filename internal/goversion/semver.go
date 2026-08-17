package goversion

import (
	"strings"

	"golang.org/x/mod/semver"
)

// Compare compares two Go semantic versions. It accepts an optional leading v
// and the OSV sentinel "0". It returns -1, 0, or 1.
func Compare(a, b string) int {
	if a == b {
		return 0
	}
	if a == "0" {
		return -1
	}
	if b == "0" {
		return 1
	}

	a = NormalizeForGo(a)
	b = NormalizeForGo(b)
	if semver.IsValid(a) && semver.IsValid(b) {
		return semver.Compare(a, b)
	}

	// Keep malformed advisory data deterministic without pretending it is valid semver.
	return strings.Compare(a, b)
}

// Max returns the greater of two Go semantic versions.
func Max(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if Compare(a, b) >= 0 {
		return a
	}
	return b
}

// NormalizeForGo adds the leading v expected by Go module versions when needed.
func NormalizeForGo(v string) string {
	if v == "" || v == "0" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
