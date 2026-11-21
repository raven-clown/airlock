package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/raven-clown/airlock/audit"
)

const auditColumns = "occurred_at, kind, request_id, trace_id, session_id, instance, subject, groups_json, auth, project, server, tool, decision, rule, outcome, duration_ms, args_json, error, action, resource, route"

// InsertAudit stores events. It does not move the revision.
func (s *Store) InsertAudit(ctx context.Context, org string, events []audit.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storing audit records: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.insertEvents(ctx, tx, org, events); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storing audit records: %w", err)
	}
	return nil
}

func (s *Store) insertEvents(ctx context.Context, tx *sql.Tx, org string, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, s.q("INSERT INTO audit_events (org_id, "+auditColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
	if err != nil {
		return fmt.Errorf("storing audit records: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, e := range events {
		groups, err := jsonOrEmpty(e.Groups, len(e.Groups) == 0)
		if err != nil {
			return err
		}
		args, err := jsonOrEmpty(e.Args, len(e.Args) == 0)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, org, millis(e.Time), e.Kind, e.RequestID, e.TraceID, e.SessionID, e.Instance, e.Subject,
			groups, e.Auth, e.Project, e.Server, e.Tool, e.Decision, e.Rule, e.Outcome, e.DurationMS, args, e.Error,
			e.Action, e.Resource, e.Route); err != nil {
			return fmt.Errorf("storing audit records: %w", err)
		}
	}
	return nil
}

func jsonOrEmpty(v any, empty bool) (string, error) {
	if empty {
		return "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encoding audit record: %w", err)
	}
	return string(b), nil
}

// AuditQuery filters ListAudit. Zero fields match everything.
type AuditQuery struct {
	Kind, Subject, Server, Tool, Outcome string
	// Since is inclusive and Until exclusive.
	Since, Until time.Time
	// BeforeTime and BeforeID return only records after that one in the newest-first order,
	// for paging. Set both, from the last record of the previous page.
	BeforeTime time.Time
	BeforeID   int64
	// Limit <= 0 means all.
	Limit int
}

// ListAudit returns the matching events, newest first.
func (s *Store) ListAudit(ctx context.Context, org string, q AuditQuery) ([]audit.Event, error) {
	where := []string{"org_id = ?"}
	args := []any{org}
	for _, f := range []struct{ col, v string }{
		{"kind", q.Kind}, {"subject", q.Subject}, {"server", q.Server}, {"tool", q.Tool}, {"outcome", q.Outcome},
	} {
		if f.v != "" {
			where = append(where, f.col+" = ?")
			args = append(args, f.v)
		}
	}
	if !q.Since.IsZero() {
		where = append(where, "occurred_at >= ?")
		args = append(args, millis(q.Since))
	}
	if !q.Until.IsZero() {
		where = append(where, "occurred_at < ?")
		args = append(args, millis(q.Until))
	}
	if q.BeforeID > 0 {
		at := millis(q.BeforeTime)
		where = append(where, "(occurred_at < ? OR (occurred_at = ? AND id < ?))")
		args = append(args, at, at, q.BeforeID)
	}
	// Newest first by the time of the event, not by when the record was written: a tool call
	// is recorded when it ends. The id breaks ties, so pages stay stable.
	query := "SELECT id, " + auditColumns + " FROM audit_events WHERE " + strings.Join(where, " AND ") + " ORDER BY occurred_at DESC, id DESC"
	if q.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, q.Limit)
	}
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("listing audit records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []audit.Event{}
	for rows.Next() {
		var e audit.Event
		var at int64
		var groups, eargs string
		if err := rows.Scan(&e.ID, &at, &e.Kind, &e.RequestID, &e.TraceID, &e.SessionID, &e.Instance, &e.Subject, &groups, &e.Auth,
			&e.Project, &e.Server, &e.Tool, &e.Decision, &e.Rule, &e.Outcome, &e.DurationMS, &eargs, &e.Error,
			&e.Action, &e.Resource, &e.Route); err != nil {
			return nil, fmt.Errorf("listing audit records: %w", err)
		}
		e.Time = fromMillis(at)
		if groups != "" {
			if err := json.Unmarshal([]byte(groups), &e.Groups); err != nil {
				return nil, fmt.Errorf("decoding audit groups: %w", err)
			}
		}
		if eargs != "" {
			if err := json.Unmarshal([]byte(eargs), &e.Args); err != nil {
				return nil, fmt.Errorf("decoding audit args: %w", err)
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing audit records: %w", err)
	}
	return out, nil
}

// DeleteAuditBefore removes events older than before and returns how many went.
func (s *Store) DeleteAuditBefore(ctx context.Context, org string, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.q("DELETE FROM audit_events WHERE org_id = ? AND occurred_at < ?"), org, millis(before))
	if err != nil {
		return 0, fmt.Errorf("deleting old audit records: %w", err)
	}
	return res.RowsAffected()
}

type auditSink struct {
	s   *Store
	org string
}

// AuditSink returns an audit.Sink that writes into the org's audit table.
func (s *Store) AuditSink(org string) audit.Sink { return &auditSink{s: s, org: org} }

func (a *auditSink) Write(ctx context.Context, events []audit.Event) error {
	return a.s.InsertAudit(ctx, a.org, events)
}

func (a *auditSink) Close() error { return nil }
