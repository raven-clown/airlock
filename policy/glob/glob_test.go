package glob

import (
	"strings"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"github__create_issue", "github__create_issue", true},
		{"github__create_issue", "github__create_issues", false},
		{"github__*", "github__create_issue", true},
		{"github__*", "github__", true},
		{"github__*", "gitlab__x", false},
		{"*_issue", "github__create_issue", true},
		{"*_issue", "github__create_issues", false},
		{"files__read_*_v2", "files__read_big_v2", true},
		{"files__read_*_v2", "files__read__v2", true},
		{"files__read_*_v2", "files__read_v2", false},
		{"*__*__*", "a__b__c", true},
		{"*__*__*", "a__b", false},
		{"**", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"a?c", "abc", false},
		{"a?c", "a?c", true},
		{"[ab]", "a", false},
		{"[ab]", "[ab]", true},
		{"GitHub__*", "github__x", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+" "+tt.name, func(t *testing.T) {
			if got := Match(tt.pattern, tt.name); got != tt.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}

func TestMatchNoBacktracking(t *testing.T) {
	done := make(chan bool)
	go func() { done <- Match("*a*a*a*a*a*b", strings.Repeat("a", 10000)) }()
	select {
	case got := <-done:
		if got {
			t.Error("Match = true, want false")
		}
	case <-time.After(time.Second):
		t.Fatal("Match did not finish within 1s")
	}
}
