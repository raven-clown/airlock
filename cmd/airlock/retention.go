package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/raven-clown/airlock/internal/store"
)

// runRetention deletes audit records older than retention now and then every interval, until ctx ends.
func runRetention(ctx context.Context, st *store.Store, org string, every, retention time.Duration, now func() time.Time, log *slog.Logger) {
	prune := func() {
		n, err := st.DeleteAuditBefore(ctx, org, now().Add(-retention))
		switch {
		case err != nil && ctx.Err() == nil:
			log.Error("deleting old audit records", "error", err)
		case n > 0:
			log.Info("deleted old audit records", "count", n)
		}
	}
	prune()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}
