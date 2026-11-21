package naming

import "testing"

// FuzzJoinSplit checks that every name Join builds splits back into the same server and tool.
func FuzzJoinSplit(f *testing.F) {
	f.Add("github", "create_issue")
	f.Add("a", "__x")
	f.Add("fs-1", "read.file")
	f.Add("Bad", "x")
	f.Add("a", "")
	f.Fuzz(func(t *testing.T, server, tool string) {
		name, err := Join(server, tool)
		if err != nil {
			return
		}
		if len(name) > maxToolName {
			t.Fatalf("Join(%q, %q) = %q, longer than %d", server, tool, name, maxToolName)
		}
		s, tl, ok := Split(name)
		if !ok || s != server || tl != tool {
			t.Fatalf("Split(%q) = %q, %q, %v, want %q, %q", name, s, tl, ok, server, tool)
		}
	})
}
