package glob

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzMatch compares Match with the same pattern written as an anchored regular expression.
func FuzzMatch(f *testing.F) {
	f.Add("github__*", "github__create_issue")
	f.Add("*__delete_*", "fs__delete_file")
	f.Add("a*b*c", "abbbc")
	f.Add("**", "")
	f.Add("*x", "\xff")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		if !utf8.ValidString(pattern) || !utf8.ValidString(name) {
			return
		}
		parts := strings.Split(pattern, "*")
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		want := regexp.MustCompile(`^(?s:` + strings.Join(parts, ".*") + `)$`).MatchString(name)
		if got := Match(pattern, name); got != want {
			t.Fatalf("Match(%q, %q) = %v, want %v", pattern, name, got, want)
		}
	})
}
