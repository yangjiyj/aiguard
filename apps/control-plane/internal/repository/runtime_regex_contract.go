package repository

import "regexp"

// MaxRuntimeRegexPatternBytes is shared with the control-plane compiler and
// security-engine custom rule loader. The engine consumes Python regex syntax,
// so this contract intentionally does not compile patterns with Go RE2.
const MaxRuntimeRegexPatternBytes = 1000

var (
	nestedRuntimeRegexQuantifier = regexp.MustCompile(`\([^()]*[+*][^()]*\)[*+{]`)
	repeatedRuntimeRegexBranch   = regexp.MustCompile(`\([^()]*\|[^()]*\)[*+{]`)
)

// IsSafeRuntimeRegex applies the same ReDoS admission contract used when the
// rule pack is compiled. Python syntax validation remains the engine's job.
func IsSafeRuntimeRegex(pattern string) bool {
	if pattern == "" || len(pattern) > MaxRuntimeRegexPatternBytes {
		return false
	}
	return !nestedRuntimeRegexQuantifier.MatchString(pattern) &&
		!repeatedRuntimeRegexBranch.MatchString(pattern)
}
