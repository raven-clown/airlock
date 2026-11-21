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
	f.Fuzz(func(t *testing.T, s, value string) {
		if strings.Contains(value, "${") {
			return
		}
		out, err := Expand(s, func(string) (string, bool) { return value, true })
		if err != nil {
			t.Fatalf("Expand(%q) with every name set: %v", s, err)
		}
		if varRef.MatchString(out) && !varRef.MatchString(s) {
			t.Fatalf("Expand(%q) = %q added a reference", s, out)
		}
		_, err = Expand(s, func(string) (string, bool) { return "", false })
		if (err != nil) != varRef.MatchString(s) {
			t.Fatalf("Expand(%q) with no names set: err = %v", s, err)
		}
	})
}
