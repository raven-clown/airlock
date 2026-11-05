package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
)

func TestRetention(t *testing.T) {
	st, err := store.Open(context.Background(), "sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "a.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	old := audit.Event{Time: now.Add(-31 * 24 * time.Hour), Kind: audit.KindTool}
	recent := audit.Event{Time: now.Add(-time.Hour), Kind: audit.KindTool}
	if err := st.InsertAudit(context.Background(), store.DefaultOrg, []audit.Event{old, recent}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runRetention(ctx, st, store.DefaultOrg, time.Hour, 30*24*time.Hour, func() time.Time { return now }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	waitFor(t, "the old record to go", func() bool {
		events, err := st.ListAudit(context.Background(), store.DefaultOrg, 0)
		return err == nil && len(events) == 1 && events[0].Time.Equal(recent.Time)
	})
	cancel()
	<-done
}

func TestReadyHidesStoreErrors(t *testing.T) {
	st, err := store.Open(context.Background(), "sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "a.db")))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	var logs syncBuffer
	check := ready(runtime.NewHolder(&runtime.Snapshot{}), backend.NewSet(backend.Deps{}), st, slog.New(slog.NewJSONHandler(&logs, nil)))
	err = check()
	if err == nil || err.Error() != "store unavailable" {
		t.Errorf("ready error = %v, want store unavailable", err)
	}
	if !strings.Contains(logs.String(), "closed") {
		t.Errorf("the store error is not logged: %s", logs.String())
	}
}
