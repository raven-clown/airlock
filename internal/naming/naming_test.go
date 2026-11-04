package naming

import (
	"strings"
	"testing"
)

func TestValidServerName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"github", true},
		{"a", true},
		{"my-server-2", true},
		{strings.Repeat("a", 32), true},
		{"", false},
		{"GitHub", false},
		{"my_server", false},
		{"-lead", false},
		{strings.Repeat("a", 33), false},
		{"a__b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidServerName(tt.name); got != tt.want {
				t.Errorf("ValidServerName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestJoin(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		tool    string
		want    string
		wantErr string
	}{
		{name: "simple", server: "github", tool: "create_issue", want: "github__create_issue"},
		{name: "dots and dashes", server: "fs", tool: "read-file.v2", want: "fs__read-file.v2"},
		{name: "exactly 128", server: "s", tool: strings.Repeat("t", 125), want: "s__" + strings.Repeat("t", 125)},
		{name: "129 is too long", server: "s", tool: strings.Repeat("t", 126), wantErr: "longer than 128"},
		{name: "space", server: "s", tool: "bad name", wantErr: `"bad name"`},
		{name: "empty tool", server: "s", tool: "", wantErr: "empty"},
		{name: "invalid server", server: "Bad", tool: "x", wantErr: `"Bad"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Join(tt.server, tt.tool)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Join error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Join: %v", err)
			}
			if got != tt.want {
				t.Errorf("Join = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplit(t *testing.T) {
	tests := []struct {
		in         string
		wantServer string
		wantTool   string
		wantOK     bool
	}{
		{"github__create__issue", "github", "create__issue", true},
		{"github__x", "github", "x", true},
		{"nosep", "", "", false},
		{"__x", "", "x", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			s, tool, ok := Split(tt.in)
			if s != tt.wantServer || tool != tt.wantTool || ok != tt.wantOK {
				t.Errorf("Split(%q) = %q, %q, %v, want %q, %q, %v", tt.in, s, tool, ok, tt.wantServer, tt.wantTool, tt.wantOK)
			}
		})
	}
}
