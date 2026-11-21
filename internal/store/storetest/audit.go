package storetest

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/internal/store"
)

var auditTests = []subtest{
	{"AuditRoundTrip", testAuditRoundTrip},
	{"AuditRetention", testAuditRetention},
	{"AuditNoRevision", testAuditNoRevision},
	{"AuditSink", testAuditSink},
	{"AuditFilters", testAuditFilters},
	{"AuditPaging", testAuditPaging},
	{"WriteWithAudit", testWriteWithAudit},
}

func fullEvent(at time.Time) audit.Event {
	return audit.Event{
		Time: at, Kind: audit.KindTool, RequestID: "req", TraceID: "trace", SessionID: "sess", Instance: "inst",
		Subject: "alice", Groups: []string{"eng", "ops"}, Auth: "apikey", Project: "p", Server: "github", Tool: "create_issue",
		Decision: "allow", Rule: "eng", Outcome: audit.OutcomeOK, DurationMS: 412, Args: map[string]any{"title": "x"}, Error: "boom",
		Action: "create", Resource: "rules/eng", Route: "POST /admin/v1/rules",
	}
}

// listAudit returns the org's events with their ids cleared, after checking the ids go down.
func listAudit(t *testing.T, st *store.Store, org string) []audit.Event {
	t.Helper()
	return query(t, st, org, store.AuditQuery{})
}

func query(t *testing.T, st *store.Store, org string, q store.AuditQuery) []audit.Event {
	t.Helper()
	got, err := st.ListAudit(context.Background(), org, q)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if got[i].ID <= 0 || (i > 0 && got[i].ID >= got[i-1].ID) {
			t.Fatalf("ids not newest first: %d after %d", got[i].ID, got[max(i-1, 0)].ID)
		}
	}
	for i := range got {
		got[i].ID = 0
	}
	return got
}

func testAuditFilters(t *testing.T, st *store.Store, org string) {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{Time: base, Kind: audit.KindTool, Subject: "alice", Server: "github", Tool: "create_issue", Outcome: audit.OutcomeOK},
		{Time: base.Add(time.Hour), Kind: audit.KindTool, Subject: "bob", Server: "files", Tool: "read", Outcome: audit.OutcomeDenied},
		{Time: base.Add(2 * time.Hour), Kind: audit.KindAdmin, Subject: "alice", Action: "create", Resource: "rules/eng"},
	}
	if err := st.InsertAudit(context.Background(), org, events); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		q    store.AuditQuery
		want int
	}{
		{"all", store.AuditQuery{}, 3},
		{"kind", store.AuditQuery{Kind: audit.KindAdmin}, 1},
		{"subject", store.AuditQuery{Subject: "alice"}, 2},
		{"server", store.AuditQuery{Server: "files"}, 1},
		{"tool", store.AuditQuery{Tool: "create_issue"}, 1},
		{"outcome", store.AuditQuery{Outcome: audit.OutcomeDenied}, 1},
		{"since", store.AuditQuery{Since: base.Add(time.Hour)}, 2},
		{"until", store.AuditQuery{Until: base.Add(time.Hour)}, 1},
		{"limit", store.AuditQuery{Limit: 2}, 2},
		{"subject and kind", store.AuditQuery{Subject: "alice", Kind: audit.KindTool}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := query(t, st, org, tc.q); len(got) != tc.want {
				t.Fatalf("got %d records, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

func testAuditPaging(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		if err := st.InsertAudit(ctx, org, []audit.Event{{Time: at, Kind: audit.KindTool, Tool: string(rune('a' + i))}}); err != nil {
			t.Fatal(err)
		}
	}
	var tools string
	var before int64
	for range 3 {
		page, err := st.ListAudit(ctx, org, store.AuditQuery{BeforeID: before, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			tools += e.Tool
		}
		if len(page) == 0 {
			break
		}
		before = page[len(page)-1].ID
	}
	if tools != "edcba" {
		t.Fatalf("pages gave %q", tools)
	}
}

func testWriteWithAudit(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	ev := func(action string) audit.Event {
		return audit.Event{Time: time.Now().UTC().Truncate(time.Millisecond), Kind: audit.KindAdmin, Action: action, Resource: "rules/r"}
	}
	if _, err := st.Create(ctx, org, store.KindRules, "r", spec("a"), ev("create")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, org, store.KindRules, "r", 1, spec("b"), ev("update")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, org, store.KindRules, "r", 1, spec("c"), ev("stale")); !errors.Is(err, store.ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := st.Create(ctx, org, store.KindRules, "r", spec("d"), ev("again")); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	if err := st.Delete(ctx, org, store.KindRules, "r", 2, ev("delete")); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range listAudit(t, st, org) {
		actions = append(actions, e.Action)
	}
	if strings.Join(actions, ",") != "delete,update,create" {
		t.Fatalf("audit actions %v; failed writes must leave none", actions)
	}
}

func testAuditRoundTrip(t *testing.T, st *store.Store, org string) {
	at := time.Date(2026, 11, 4, 10, 15, 2, 114_000_000, time.UTC)
	full := fullEvent(at)
	bare := audit.Event{Time: at.Add(time.Second), Kind: audit.KindAdmin}
	if err := st.InsertAudit(context.Background(), org, []audit.Event{full, bare}); err != nil {
		t.Fatal(err)
	}
	got := listAudit(t, st, org)
	if len(got) != 2 {
		t.Fatalf("got %d events", len(got))
	}
	if !reflect.DeepEqual(got[0], bare) {
		t.Errorf("newest = %+v, want %+v", got[0], bare)
	}
	if !reflect.DeepEqual(got[1], full) {
		t.Errorf("oldest = %+v, want %+v", got[1], full)
	}
	if other := listAudit(t, st, NewOrg(t)); len(other) != 0 {
		t.Errorf("another org sees %d events", len(other))
	}
}

func testAuditRetention(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	cutoff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	old, recent := fullEvent(cutoff.Add(-time.Hour)), fullEvent(cutoff.Add(time.Hour))
	other := NewOrg(t)
	for _, o := range []string{org, other} {
		if err := st.InsertAudit(ctx, o, []audit.Event{old, recent}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.DeleteAuditBefore(ctx, org, cutoff)
	if err != nil || n != 1 {
		t.Fatalf("DeleteAuditBefore = %d, %v, want 1", n, err)
	}
	if got := listAudit(t, st, org); len(got) != 1 || !got[0].Time.Equal(recent.Time) {
		t.Errorf("left %+v", got)
	}
	if got := listAudit(t, st, other); len(got) != 2 {
		t.Errorf("another org lost rows: %d left", len(got))
	}
}

func testAuditNoRevision(t *testing.T, st *store.Store, org string) {
	mustCreate(t, st, org, store.KindRules, "r", "x")
	before := revision(t, st, org)
	if err := st.InsertAudit(context.Background(), org, []audit.Event{fullEvent(time.Now())}); err != nil {
		t.Fatal(err)
	}
	if after := revision(t, st, org); after != before {
		t.Errorf("revision moved from %d to %d", before, after)
	}
}

func testAuditSink(t *testing.T, st *store.Store, org string) {
	sink := st.AuditSink(org)
	if err := sink.Write(context.Background(), []audit.Event{fullEvent(time.Now())}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if got := listAudit(t, st, org); len(got) != 1 {
		t.Errorf("got %d events through the sink", len(got))
	}
}
