package config

import (
	"strings"
	"testing"
)

// FuzzParse feeds Parse any document and one AIRLOCK_ override. It must return a config or an error, never panic.
func FuzzParse(f *testing.F) {
	f.Add("listen_addr: ${ADDR}\nservers:\n  - name: github\n    transport: stdio\n    command: gh-mcp\n    env:\n      TOKEN: ${GH}\n", "STDIO__IDENTITY", "me")
	f.Add("servers:\n  - {name: a, transport: streamable_http, url: http://x/mcp, auth: {mode: forward}}\n  - {name: b, transport: stdio, command: b, call_timeout: 5s}\n", "AUDIT__BUFFER_SIZE", "10")
	f.Add("audit:\n  sinks: [{kind: file, path: /tmp/a.log}]\n  retention: 24h\n", "AUDIT__INCLUDE_ARGS", "true")
	f.Add("- a\n- b\n", "LISTEN_ADDR", "0.0.0.0:9")
	f.Add("&a [*a]", "SERVERS", "x")
	f.Fuzz(func(t *testing.T, doc, key, value string) {
		env := Env{"ADDR": "127.0.0.1:1", "AIRLOCK_" + key: value}
		cfg, err := Parse([]byte(doc), env)
		if (cfg == nil) == (err == nil) {
			t.Fatalf("Parse(%q) = %v, %v", doc, cfg, err)
		}
	})
}

// FuzzExpand checks that Expand leaves no ${NAME} reference behind when every name is set.
func FuzzExpand(f *testing.F) {
	f.Add("${A}-${B_1}", "x")
	f.Add("$${A}}", "${A}")
	f.Add("${", "")
	f.Add("${A}${A}", "$")
	f.Add("${A:-fallback}", "x")
	f.Add("${A:-}", "")
	f.Add("${A:-${}B}", "x")
	f.Fuzz(func(t *testing.T, s, value string) {
		if strings.Contains(value, "${") {
			return
		}
		out, err := Expand(s, func(string) (string, bool) { return value, true })
		if err != nil {
			t.Fatalf("Expand(%q) with every name set: %v", s, err)
		}
		// An empty value selects the default, which can form a new ${NAME} with the
		// text after the reference. A non-empty value is copied through as itself.
		if value != "" && varRef.MatchString(out) && !varRef.MatchString(s) {
			t.Fatalf("Expand(%q) = %q added a reference", s, out)
		}
		_, err = Expand(s, func(string) (string, bool) { return "", false })
		if (err != nil) != hasRequiredRef(s) {
			t.Fatalf("Expand(%q) with no names set: err = %v", s, err)
		}
	})
}

// hasRequiredRef reports whether s contains a ${NAME} that Expand must resolve.
// The default of ${NAME:-default} ends at the next }, so a ${...} inside it is not its own reference.
func hasRequiredRef(s string) bool {
	for _, m := range expandRef.FindAllStringSubmatch(s, -1) {
		if m[2] == "" {
			return true
		}
	}
	return false
}
