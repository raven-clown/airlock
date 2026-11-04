package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/policy"
)

var designRules = []Rule{
	{Name: "eng-github", Subjects: []string{"group:eng"}, Allow: []string{"github__*", "files__*"}, Deny: []string{"github__delete_*"}},
	{Name: "interns-read", Subjects: []string{"group:interns"}, Allow: []string{"files__read_*", "files__list_*"}},
	{Name: "ci-bot", Subjects: []string{"key:ci-bot"}, Allow: []string{"github__create_issue"}},
	{Name: "everyone-memory", Subjects: []string{"*"}, Allow: []string{"logbook__*"}},
}

var (
	alice = &auth.Identity{Subject: "alice", Groups: []string{"eng"}, Method: "oidc"}
	bob   = &auth.Identity{Subject: "bob", Groups: []string{"interns"}, Method: "oidc"}
	ci    = &auth.Identity{Subject: "key:ci-bot", KeyName: "ci-bot", Method: "apikey"}
)

type decideCase struct {
	name       string
	id         *auth.Identity
	tool       string
	wantAllow  bool
	wantRule   string
	wantReason string
}

var decideCases = []decideCase{
	{"eng creates issue", alice, "github__create_issue", true, "eng-github", "allowed by pattern github__*"},
	{"eng deletes repo", alice, "github__delete_repo", false, "eng-github", "denied by pattern github__delete_*"},
	{"intern creates issue", bob, "github__create_issue", false, DefaultDeny, "no rule allows github__create_issue"},
	{"intern reads file", bob, "files__read_file", true, "interns-read", "allowed by pattern files__read_*"},
	{"ci creates issue", ci, "github__create_issue", true, "ci-bot", "allowed by pattern github__create_issue"},
	{"ci reads file", ci, "files__read_file", false, DefaultDeny, "no rule allows files__read_file"},
	{"anyone recalls", bob, "logbook__recall", true, "everyone-memory", "allowed by pattern logbook__*"},
}

func TestDecide(t *testing.T) {
	p, err := New(designRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range decideCases {
		t.Run(tt.name, func(t *testing.T) {
			d := p.Decide(context.Background(), policy.Request{Identity: tt.id, Server: strings.Split(tt.tool, "__")[0], Tool: tt.tool})
			if d.Allow != tt.wantAllow || d.Rule != tt.wantRule || d.Reason != tt.wantReason {
				t.Errorf("Decide = %+v, want allow=%v rule=%q reason=%q", d, tt.wantAllow, tt.wantRule, tt.wantReason)
			}
		})
	}
}

func TestDenyInOtherRuleWins(t *testing.T) {
	p, err := New([]Rule{
		{Name: "a-allow", Subjects: []string{"group:eng"}, Allow: []string{"*"}},
		{Name: "b-deny", Subjects: []string{"user:alice"}, Deny: []string{"github__*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := p.Decide(context.Background(), policy.Request{Identity: alice, Tool: "github__x"})
	if d.Allow || d.Rule != "b-deny" {
		t.Errorf("Decide = %+v, want deny by b-deny", d)
	}
}

func TestNoIdentityDenied(t *testing.T) {
	p, err := New(designRules)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Decide(context.Background(), policy.Request{Tool: "logbook__recall"}); d.Allow {
		t.Error("a request with no identity was allowed")
	}
}

func permutations(rs []Rule) [][]Rule {
	if len(rs) <= 1 {
		return [][]Rule{rs}
	}
	var out [][]Rule
	for i := range rs {
		rest := append(append([]Rule{}, rs[:i]...), rs[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]Rule{rs[i]}, p...))
		}
	}
	return out
}

func TestDecideOrderIndependent(t *testing.T) {
	for _, order := range permutations(designRules) {
		p, err := New(order)
		if err != nil {
			t.Fatal(err)
		}
		for _, tt := range decideCases {
			d := p.Decide(context.Background(), policy.Request{Identity: tt.id, Tool: tt.tool})
			if d.Allow != tt.wantAllow || d.Rule != tt.wantRule {
				t.Fatalf("order %v, %s: Decide = %+v", names(order), tt.name, d)
			}
		}
	}
}

func names(rs []Rule) []string {
	var n []string
	for _, r := range rs {
		n = append(n, r.Name)
	}
	return n
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		rules   []Rule
		wantErr string
	}{
		{"empty name", []Rule{{Subjects: []string{"*"}}}, "rules[0]: name is empty"},
		{"duplicate", []Rule{{Name: "a", Subjects: []string{"*"}}, {Name: "a", Subjects: []string{"*"}}}, `rules[1]: duplicate name "a"`},
		{"no subjects", []Rule{{Name: "a"}}, `rule "a": no subjects`},
		{"bad subject", []Rule{{Name: "a", Subjects: []string{"team:x"}}}, `rule "a": unknown subject "team:x"`},
		{"empty subject value", []Rule{{Name: "a", Subjects: []string{"user:"}}}, `rule "a": unknown subject "user:"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("New error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestRegistered(t *testing.T) {
	f, ok := policy.Lookup("rules")
	if !ok {
		t.Fatal("rules is not registered")
	}
	p, err := f([]byte(`{"rules":[{"name":"a","subjects":["*"],"allow":["x__*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Decide(context.Background(), policy.Request{Identity: alice, Tool: "x__y"}); !d.Allow {
		t.Errorf("Decide = %+v", d)
	}
	if _, err := f([]byte(`{"rules":[{"name":""}]}`)); err == nil {
		t.Error("invalid rules accepted")
	}
}
