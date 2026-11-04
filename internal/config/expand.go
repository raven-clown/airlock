package config

import (
	"fmt"
	"regexp"
)

var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Expand replaces each ${NAME} in s with its value from lookup.
func Expand(s string, lookup func(string) (string, bool)) (string, error) {
	var missing string
	out := varRef.ReplaceAllStringFunc(s, func(ref string) string {
		name := ref[2 : len(ref)-1]
		v, ok := lookup(name)
		if !ok && missing == "" {
			missing = name
		}
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("variable %s is not set", missing)
	}
	return out, nil
}
