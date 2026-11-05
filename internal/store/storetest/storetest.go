// Package storetest is the test suite every store driver must pass.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/raven-clown/airlock/internal/store"
)

type subtest struct {
	name string
	fn   func(t *testing.T, st *store.Store, org string)
}

// Run runs the suite against the store open returns. Each subtest uses its own org,
// so one database can serve the whole run.
func Run(t *testing.T, open func(t *testing.T) *store.Store) {
	st := open(t)
	tests := []subtest{
		{"CreateGet", testCreateGet},
		{"List", testList},
		{"Update", testUpdate},
		{"Delete", testDelete},
		{"Revision", testRevision},
		{"AllKinds", testAllKinds},
	}
	tests = append(tests, provisionTests...)
	tests = append(tests, auditTests...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.fn(t, st, NewOrg(t)) })
	}
}

// NewOrg returns a random org name.
func NewOrg(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "test-" + hex.EncodeToString(b)
}

func spec(v string) json.RawMessage { return json.RawMessage(fmt.Sprintf(`{"v":%q}`, v)) }

func specValue(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var s struct{ V string }
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("spec %s: %v", raw, err)
	}
	return s.V
}

func revision(t *testing.T, st *store.Store, org string) int64 {
	t.Helper()
	r, err := st.Revision(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustCreate(t *testing.T, st *store.Store, org string, k store.Kind, name, v string) store.Row {
	t.Helper()
	r, err := st.Create(context.Background(), org, k, name, spec(v))
	if err != nil {
		t.Fatalf("Create %s %s: %v", k, name, err)
	}
	return r
}

func testCreateGet(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	created := mustCreate(t, st, org, store.KindServers, "github", "one")
	if created.Version != 1 || created.Source != store.SourceAPI || created.CreatedAt.IsZero() || !created.UpdatedAt.Equal(created.CreatedAt) {
		t.Errorf("created = %+v", created)
	}
	got, err := st.Get(ctx, org, store.KindServers, "github")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "github" || got.Version != 1 || got.Source != store.SourceAPI || specValue(t, got.Spec) != "one" || !got.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("got = %+v", got)
	}
	if _, err := st.Create(ctx, org, store.KindServers, "github", spec("two")); !errors.Is(err, store.ErrExists) {
		t.Errorf("second Create error = %v, want ErrExists", err)
	}
	if _, err := st.Get(ctx, org, store.KindServers, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get missing error = %v, want ErrNotFound", err)
	}
	if _, err := st.Get(ctx, NewOrg(t), store.KindServers, "github"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get from another org error = %v, want ErrNotFound", err)
	}
}

func names(rows []store.Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Name
	}
	return out
}

func testList(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	for _, n := range []string{"e", "b", "d", "a", "c"} {
		mustCreate(t, st, org, store.KindRules, n, n)
	}
	mustCreate(t, st, NewOrg(t), store.KindRules, "aa", "other org")
	tests := []struct {
		after string
		limit int
		want  string
	}{
		{"", 0, "[a b c d e]"},
		{"", 2, "[a b]"},
		{"b", 2, "[c d]"},
		{"d", 2, "[e]"},
		{"e", 2, "[]"},
	}
	for _, tt := range tests {
		rows, err := st.List(ctx, org, store.KindRules, tt.after, tt.limit)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(names(rows)); got != tt.want {
			t.Errorf("List(after %q, limit %d) = %s, want %s", tt.after, tt.limit, got, tt.want)
		}
	}
}

func testUpdate(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	created := mustCreate(t, st, org, store.KindRules, "r", "one")
	updated, err := st.Update(ctx, org, store.KindRules, "r", 1, spec("two"))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || specValue(t, updated.Spec) != "two" || updated.UpdatedAt.Before(created.UpdatedAt) || !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("updated = %+v", updated)
	}
	if _, err := st.Update(ctx, org, store.KindRules, "r", 1, spec("three")); !errors.Is(err, store.ErrVersionConflict) {
		t.Errorf("stale Update error = %v, want ErrVersionConflict", err)
	}
	if _, err := st.Update(ctx, org, store.KindRules, "missing", 1, spec("x")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing Update error = %v, want ErrNotFound", err)
	}
	got, err := st.Get(ctx, org, store.KindRules, "r")
	if err != nil || specValue(t, got.Spec) != "two" {
		t.Errorf("after failed updates got %+v, %v", got, err)
	}
}

func testDelete(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	mustCreate(t, st, org, store.KindAPIKeys, "k", "one")
	if err := st.Delete(ctx, org, store.KindAPIKeys, "k", 2); !errors.Is(err, store.ErrVersionConflict) {
		t.Errorf("stale Delete error = %v, want ErrVersionConflict", err)
	}
	if err := st.Delete(ctx, org, store.KindAPIKeys, "k", 1); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, org, store.KindAPIKeys, "k", 1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second Delete error = %v, want ErrNotFound", err)
	}
}

func testRevision(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	if r := revision(t, st, org); r != 0 {
		t.Fatalf("new org revision = %d", r)
	}
	mustCreate(t, st, org, store.KindRules, "r", "one")
	_, _ = st.Create(ctx, org, store.KindRules, "r", spec("dup"))
	if _, err := st.Update(ctx, org, store.KindRules, "r", 1, spec("two")); err != nil {
		t.Fatal(err)
	}
	_, _ = st.Update(ctx, org, store.KindRules, "r", 1, spec("stale"))
	if err := st.Delete(ctx, org, store.KindRules, "r", 2); err != nil {
		t.Fatal(err)
	}
	if r := revision(t, st, org); r != 3 {
		t.Errorf("revision = %d, want 3", r)
	}
	other := NewOrg(t)
	mustCreate(t, st, other, store.KindRules, "r", "x")
	if r := revision(t, st, org); r != 3 {
		t.Errorf("revision after another org's write = %d, want 3", r)
	}
}

func testAllKinds(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	for _, k := range store.Kinds {
		mustCreate(t, st, org, k, "x", string(k))
		got, err := st.Get(ctx, org, k, "x")
		if err != nil || specValue(t, got.Spec) != string(k) {
			t.Errorf("%s: got %+v, %v", k, got, err)
		}
		if err := st.Delete(ctx, org, k, "x", 1); err != nil {
			t.Errorf("%s: Delete: %v", k, err)
		}
	}
	if _, err := st.Get(ctx, org, store.Kind("nope"), "x"); err == nil {
		t.Error("unknown kind accepted")
	}
}
