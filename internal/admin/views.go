package admin

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/naming"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/policy"
)

func (h *handler) status(w http.ResponseWriter, _ *http.Request) {
	snap := h.d.Runtime.Current()
	now := h.d.Now()
	backends := []map[string]any{}
	if h.d.Backends != nil {
		for _, b := range h.d.Backends.All() {
			backends = append(backends, backendStatus(b))
		}
	}
	reload := map[string]any{}
	if st := h.d.Runtime.State(); !st.At.IsZero() {
		reload["at"] = formatTime(st.At)
		if st.Error != "" {
			reload["error"] = st.Error
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        h.d.Version,
		"instance":       h.d.Instance,
		"started_at":     formatTime(h.d.Started),
		"uptime_seconds": int64(now.Sub(h.d.Started) / time.Second),
		"revision":       snap.Revision,
		"storage":        h.d.Process.Storage.Driver,
		"reload":         reload,
		"backends":       backends,
	})
}

type toolJSON struct {
	Name        string `json:"name"`
	Server      string `json:"server"`
	Tool        string `json:"tool"`
	Description string `json:"description,omitempty"`
}

func (h *handler) tools(w http.ResponseWriter, r *http.Request) {
	p, err := readPage(r)
	if err != nil {
		h.fail(w, r, "tools", err)
		return
	}
	server := r.URL.Query().Get("server")
	items := []toolJSON{}
	for _, t := range h.d.Catalog.Tools() {
		if server != "" && t.Server != server {
			continue
		}
		_, tool, _ := naming.Split(t.Name)
		items = append(items, toolJSON{Name: t.Name, Server: t.Server, Tool: tool, Description: t.Tool.Description})
	}
	writeJSON(w, http.StatusOK, keyPage(items, p, func(t toolJSON) string { return t.Name }))
}

type decisionJSON struct {
	Tool   string `json:"tool"`
	Allow  bool   `json:"allow"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

func decide(ctx context.Context, snap *runtime.Snapshot, id *auth.Identity, tool string) decisionJSON {
	srv, _, _ := naming.Split(tool)
	d := snap.Policy.Decide(ctx, policy.Request{Identity: id, Server: srv, Tool: tool})
	return decisionJSON{Tool: tool, Allow: d.Allow, Rule: d.Rule, Reason: d.Reason}
}

func (h *handler) me(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	snap := h.d.Runtime.Current()
	v := map[string]any{"subject": id.Subject, "method": id.Method, "role": snap.Role(id)}
	if len(id.Groups) > 0 {
		v["groups"] = id.Groups
	}
	if p, ok := snap.Limits.Profile(runtime.Caller(id)); ok {
		v["profile"] = p.Name
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *handler) myTools(w http.ResponseWriter, r *http.Request) {
	p, err := readPage(r)
	if err != nil {
		h.fail(w, r, "tools", err)
		return
	}
	id, _ := auth.FromContext(r.Context())
	snap := h.d.Runtime.Current()
	items := []decisionJSON{}
	for _, t := range h.d.Catalog.Tools() {
		if d := decide(r.Context(), snap, id, t.Name); d.Allow {
			items = append(items, d)
		}
	}
	writeJSON(w, http.StatusOK, keyPage(items, p, func(d decisionJSON) string { return d.Tool }))
}

type checkRequest struct {
	User   string   `json:"user"`
	Key    string   `json:"key"`
	Groups []string `json:"groups"`
	Tools  []string `json:"tools"`
}

func (h *handler) check(w http.ResponseWriter, r *http.Request) {
	raw, err := readBody(w, r)
	if err != nil {
		h.fail(w, r, "check", err)
		return
	}
	var in checkRequest
	if err := decodeStrict(raw, &in); err != nil {
		h.fail(w, r, "check", err)
		return
	}
	var id *auth.Identity
	switch {
	case in.User != "" && in.Key != "":
		h.fail(w, r, "check", invalid("key", "set user or key, not both"))
		return
	case in.Key != "":
		id = &auth.Identity{Subject: "key:" + in.Key, KeyName: in.Key, Groups: in.Groups, Method: "apikey"}
	case in.User != "":
		id = &auth.Identity{Subject: in.User, Groups: in.Groups, Method: "oidc"}
	default:
		h.fail(w, r, "check", invalid("user", "set user or key"))
		return
	}
	tools := in.Tools
	if len(tools) == 0 {
		for _, t := range h.d.Catalog.Tools() {
			tools = append(tools, t.Name)
		}
	}
	snap := h.d.Runtime.Current()
	items := make([]decisionJSON, 0, len(tools))
	for _, t := range tools {
		items = append(items, decide(r.Context(), snap, id, t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *handler) audit(w http.ResponseWriter, r *http.Request) {
	p, err := readPage(r)
	if err != nil {
		h.fail(w, r, "audit", err)
		return
	}
	query := r.URL.Query()
	q := store.AuditQuery{
		Kind: query.Get("kind"), Subject: query.Get("subject"), Server: query.Get("server"),
		Tool: query.Get("tool"), Outcome: query.Get("outcome"), Limit: p.limit + 1,
	}
	if q.Kind != "" && q.Kind != audit.KindTool && q.Kind != audit.KindAdmin {
		h.fail(w, r, "audit", invalid("kind", "kind must be tool or admin"))
		return
	}
	for _, f := range []struct {
		name string
		dst  *time.Time
	}{{"since", &q.Since}, {"until", &q.Until}} {
		if s := query.Get(f.name); s != "" {
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				h.fail(w, r, "audit", invalid(f.name, "%s must be an RFC 3339 time", f.name))
				return
			}
			*f.dst = t
		}
	}
	if p.after != "" {
		if q.BeforeID, err = strconv.ParseInt(p.after, 10, 64); err != nil || q.BeforeID < 1 {
			h.fail(w, r, "audit", invalid("cursor", "cursor is not one this API returned"))
			return
		}
	}
	// A member reads only their own records, whatever they ask for.
	id, _ := auth.FromContext(r.Context())
	if !runtime.HasRole(h.d.Runtime.Current().Role(id), config.RoleViewer) {
		q.Subject = id.Subject
	}
	events, err := h.d.Store.ListAudit(r.Context(), h.d.Org, q)
	if err != nil {
		h.fail(w, r, "audit", err)
		return
	}
	out := listJSON[audit.Event]{Items: events}
	if len(events) > p.limit {
		out.Items = events[:p.limit]
		out.NextCursor = cursor(strconv.FormatInt(events[p.limit-1].ID, 10))
	}
	writeJSON(w, http.StatusOK, out)
}
