package config

import (
	"fmt"
	"regexp"
	"strings"
)

// varRef matches ${NAME} with no default. FuzzExpand treats a match as a name that must be set.
var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandRef matches ${NAME} and ${NAME:-default}. Group 2 is ":-" plus the default,
// empty when there is no default. The default ends at the next }.
var expandRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// Expand replaces each ${NAME} in s with its value from lookup.
// ${NAME:-default} uses default when NAME is unset or empty. An unset
// ${NAME} with no default is an error. The default may be empty and ends
// at the next }.
func Expand(s string, lookup func(string) (string, bool)) (string, error) {
	var missing string
	out := expandRef.ReplaceAllStringFunc(s, func(ref string) string {
		body := ref[2 : len(ref)-1]
		name, def, hasDefault := strings.Cut(body, ":-")
		v, ok := lookup(name)
		if hasDefault && (!ok || v == "") {
			return def
		}
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
