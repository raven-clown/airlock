package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/raven-clown/airlock/internal/config"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: "airlock dev\n"},
		{name: "no command", args: nil, wantCode: 2, wantStderr: "usage: airlock <command>"},
		{name: "unknown command", args: []string{"nope"}, wantCode: 2, wantStderr: `unknown command "nope"`},
		{name: "help", args: []string{"help"}, wantCode: 0, wantStdout: "serve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, strings.NewReader(""), &stdout, &stderr, config.Env{})
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
