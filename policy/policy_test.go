package policy

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/raven-clown/airlock/auth"
)

func TestSubjects(t *testing.T) {
	tests := []struct {
		name string
		id   *auth.Identity
		want []string
	}{
		{"user", &auth.Identity{Subject: "alice", Groups: []string{"eng", "ops"}, Method: "oidc"}, []string{"user:alice", "group:eng", "group:ops", "*"}},
		{"key", &auth.Identity{Subject: "key:ci-bot", KeyName: "ci-bot", Groups: []string{"ci"}, Method: "apikey"}, []string{"key:ci-bot", "group:ci", "*"}},
		{"nil", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Subjects(tt.id); !slices.Equal(got, tt.want) {
				t.Errorf("Subjects = %v, want %v", got, tt.want)
			}
		})
	}
}

type allowAll struct{}

func (allowAll) Decide(context.Context, Request) Decision { return Decision{Allow: true} }

func TestRegister(t *testing.T) {
	Register("test-allow", func(json.RawMessage) (Policy, error) { return allowAll{}, nil })
	if _, ok := Lookup("test-allow"); !ok {
		t.Fatal("not found")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("registering twice did not panic")
		}
	}()
	Register("test-allow", func(json.RawMessage) (Policy, error) { return allowAll{}, nil })
}
