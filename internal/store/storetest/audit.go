package storetest

import (
	"context"
	"reflect"
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
}

func fullEvent(at time.Time) audit.Event {
	return audit.Event{
		Time: at, Kind: audit.KindTool, RequestID: "req", TraceID: "trace", SessionID: "sess", Instance: "inst",
		Subject: "alice", Groups: []string{"eng", "ops"}, Auth: "apikey", Project: "p", Server: "github", Tool: "create_issue",
		Decision: "allow", Rule: "eng", Outcome: audit.OutcomeOK, DurationMS: 412, Args: map[string]any{"title": "x"}, Error: "boom",
	}
}

func listAudit(t *testing.T, st *store.Store, org string) []audit.Event {
	t.Helper()
	got, err := st.ListAudit(context.Background(), org, 0)
	if err != nil {
		t.Fatal(err)
	}
	return got
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
