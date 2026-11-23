// Package agentguardmatch defines the canonical AgentGuard tool-pattern semantics
// shared by runtime evaluation and control-plane simulation.
package agentguardmatch

import (
	"path"
	"strings"
)

// Matches reports whether pattern matches a real tool name or its normalized type path.
func Matches(pattern, toolName, toolType string) bool {
	pattern = normalize(pattern)
	if pattern == "" {
		return false
	}
	name := normalize(toolName)
	kind := normalize(toolType)
	// Type wildcards are an explicit namespace rule, never a synthetic glob candidate.
	if kind != "" && pattern == kind+".*" {
		return true
	}
	for _, candidate := range candidates(name, kind) {
		if matchCandidate(pattern, candidate) {
			return true
		}
	}
	return false
}

func candidates(name, kind string) []string {
	out := make([]string, 0, 3)
	add := func(candidate string) {
		if candidate == "" {
			return
		}
		for _, existing := range out {
			if existing == candidate {
				return
			}
		}
		out = append(out, candidate)
	}

	add(name)
	if kind != "" && name != "" {
		if strings.HasPrefix(name, kind+".") {
			add(name)
		} else {
			add(kind + "." + name)
		}
	}
	return out
}

func matchCandidate(pattern, candidate string) bool {
	if candidate == "" {
		return false
	}
	if pattern == "*" || pattern == candidate {
		return true
	}
	matched, err := path.Match(pattern, candidate)
	return err == nil && matched
}

// ValidPattern reports whether a non-empty normalized pattern is a valid path glob.
func ValidPattern(pattern string) bool {
	pattern = normalize(pattern)
	if pattern == "" {
		return false
	}
	_, err := path.Match(pattern, "")
	return err == nil
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
