package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/limits"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/policy/rules"
)

const (
	defaultLimit = 50
	maxLimit     = 500
)

// kind is one resource collection and how the API reads and writes it.
type kind struct {
	path  string
	store store.Kind
	what  string
	// decode reads a write body into the spec to store. prev is the stored spec when the
	// body is a patched copy of it, nil on create.
	decode func(raw []byte, prev json.RawMessage) (name string, spec json.RawMessage, err error)
	// writeForm turns a stored spec into the body a PATCH is merged into.
	writeForm func(spec json.RawMessage) (json.RawMessage, error)
	// view turns a stored row into its API shape, without the common fields.
	view func(row store.Row) (map[string]any, error)
}

func (h *handler) kinds() []*kind {
	return []*kind{
		{path: "servers", store: store.KindServers, what: "server", decode: h.decodeServer, writeForm: serverWriteForm, view: h.viewServer},
		simple[rules.Rule]("rules", store.KindRules, "rule", func(v rules.Rule) string { return v.Name }),
		simple[config.RoleBinding]("role-bindings", store.KindRoleBindings, "role binding", func(v config.RoleBinding) string { return v.Name }),
		simple[limits.Spec]("profiles", store.KindProfiles, "profile", func(v limits.Spec) string { return v.Name }),
		simple[limits.Binding]("profile-bindings", store.KindProfileBindings, "profile binding", func(v limits.Binding) string { return v.Name }),
		{path: "api-keys", store: store.KindAPIKeys, what: "API key", decode: decodeKeyPatch, writeForm: keyWriteForm, view: viewKey},
	}
}

// simple is a kind whose API shape is its stored spec.
func simple[T any](path string, k store.Kind, what string, name func(T) string) *kind {
	return &kind{
		path: path, store: k, what: what,
		decode: func(raw []byte, _ json.RawMessage) (string, json.RawMessage, error) {
			var v T
			if err := decodeStrict(raw, &v); err != nil {
				return "", nil, err
			}
			spec, err := json.Marshal(v)
			return name(v), spec, err
		},
		writeForm: func(spec json.RawMessage) (json.RawMessage, error) { return spec, nil },
		view: func(row store.Row) (map[string]any, error) {
			var m map[string]any
			err := json.Unmarshal(row.Spec, &m)
			return m, err
		},
	}
}

// fullView is a row's API shape with the fields every resource has.
func fullView(k *kind, row store.Row) (map[string]any, error) {
	v, err := k.view(row)
	if err != nil {
		return nil, err
	}
	if v == nil {
		v = map[string]any{}
	}
	v["version"] = row.Version
	v["source"] = row.Source
	v["managed_by_file"] = row.Source == store.SourceFile
	v["created_at"] = formatTime(row.CreatedAt)
	v["updated_at"] = formatTime(row.UpdatedAt)
	return v, nil
}

type page struct {
	limit int
	after string
}

func readPage(r *http.Request) (page, error) {
	q := r.URL.Query()
	p := page{limit: defaultLimit}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxLimit {
			return p, invalid("limit", "limit must be a whole number from 1 to %d", maxLimit)
		}
		p.limit = n
	}
	if s := q.Get("cursor"); s != "" {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(raw) == 0 {
			return p, invalid("cursor", "cursor is not one this API returned")
		}
		p.after = string(raw)
	}
	return p, nil
}

func cursor(key string) string { return base64.RawURLEncoding.EncodeToString([]byte(key)) }

type listJSON[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// keyPage returns the items after p's cursor, which are sorted by key, and the next cursor.
func keyPage[T any](items []T, p page, key func(T) string) listJSON[T] {
	start := 0
	for p.after != "" && start < len(items) && key(items[start]) <= p.after {
		start++
	}
	out := listJSON[T]{Items: items[start:]}
	if len(out.Items) > p.limit {
		out.Items = out.Items[:p.limit]
		out.NextCursor = cursor(key(out.Items[p.limit-1]))
	}
	if out.Items == nil {
		out.Items = []T{}
	}
	return out
}

func (h *handler) list(k *kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := readPage(r)
		if err != nil {
			h.fail(w, r, k.path, err)
			return
		}
		rows, err := h.d.Store.List(r.Context(), h.d.Org, k.store, p.after, p.limit+1)
		if err != nil {
			h.fail(w, r, k.path, err)
			return
		}
		out := listJSON[map[string]any]{Items: make([]map[string]any, 0, len(rows))}
		if len(rows) > p.limit {
			rows = rows[:p.limit]
			out.NextCursor = cursor(rows[p.limit-1].Name)
		}
		for _, row := range rows {
			v, err := fullView(k, row)
			if err != nil {
				h.fail(w, r, k.path, err)
				return
			}
			h.hideStderr(r, v["status"])
			out.Items = append(out.Items, v)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (h *handler) get(k *kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		row, err := h.d.Store.Get(r.Context(), h.d.Org, k.store, name)
		if err != nil {
			h.fail(w, r, k.what+" "+name, err)
			return
		}
		h.answer(w, r, k, row, http.StatusOK)
	}
}

func (h *handler) answer(w http.ResponseWriter, r *http.Request, k *kind, row store.Row, status int) {
	v, err := fullView(k, row)
	if err != nil {
		h.fail(w, r, k.what+" "+row.Name, err)
		return
	}
	h.hideStderr(r, v["status"])
	writeVersioned(w, status, row.Version, v)
}

// validate refuses a change that would leave a config that does not load.
func (h *handler) validate(w http.ResponseWriter, r *http.Request, write bool, changes ...runtime.Change) bool {
	if _, err := h.d.Source.ConfigWith(r.Context(), changes...); err != nil {
		h.fail(w, r, "config", configError(err, write))
		return false
	}
	return true
}

func (h *handler) create(k *kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := readBody(w, r)
		if err != nil {
			h.fail(w, r, k.what, err)
			return
		}
		name, spec, err := k.decode(raw, nil)
		if err != nil {
			h.fail(w, r, k.what, err)
			return
		}
		if name == "" {
			h.fail(w, r, k.what, invalid("name", "name is required"))
			return
		}
		if _, err := h.d.Store.Get(r.Context(), h.d.Org, k.store, name); err == nil {
			h.fail(w, r, k.what+" "+name, store.ErrExists)
			return
		}
		if !h.validate(w, r, true, runtime.Change{Kind: k.store, Name: name, Spec: spec}) {
			return
		}
		row, err := h.d.Store.Create(r.Context(), h.d.Org, k.store, name, spec, h.event(r, "create", k.path+"/"+name))
		if err != nil {
			h.fail(w, r, k.what+" "+name, err)
			return
		}
		h.reload(r)
		h.answer(w, r, k, row, http.StatusCreated)
	}
}

// editable reads a row a write may change: not from the file, and at the version If-Match
// names when it names one.
func (h *handler) editable(r *http.Request, k *kind, name string) (store.Row, error) {
	version, err := ifMatch(r)
	if err != nil {
		return store.Row{}, err
	}
	row, err := h.d.Store.Get(r.Context(), h.d.Org, k.store, name)
	if err != nil {
		return row, err
	}
	if row.Source == store.SourceFile {
		return row, conflict("managed_by_file", "", "%s %s is managed by the config file; change it there", k.what, name)
	}
	if version > 0 && version != row.Version {
		return row, store.ErrVersionConflict
	}
	return row, nil
}

func (h *handler) patch(k *kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		row, err := h.editable(r, k, name)
		if err != nil {
			h.fail(w, r, k.what+" "+name, err)
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			h.fail(w, r, k.what, err)
			return
		}
		base, err := k.writeForm(row.Spec)
		if err != nil {
			h.fail(w, r, k.what+" "+name, err)
			return
		}
		merged, err := mergePatch(base, body)
		if err != nil {
			h.fail(w, r, k.what, err)
			return
		}
		newName, spec, err := k.decode(merged, row.Spec)
		if err != nil {
			h.fail(w, r, k.what, err)
			return
		}
		if newName != name {
			h.fail(w, r, k.what, invalid("name", "the name cannot change; create a new %s instead", k.what))
			return
		}
		if !h.validate(w, r, true, runtime.Change{Kind: k.store, Name: name, Spec: spec}) {
			return
		}
		updated, err := h.d.Store.Update(r.Context(), h.d.Org, k.store, name, row.Version, spec, h.event(r, "update", k.path+"/"+name))
		if err != nil {
			h.fail(w, r, k.what+" "+name, err)
			return
		}
		h.reload(r)
		h.answer(w, r, k, updated, http.StatusOK)
	}
}

func (h *handler) remove(k *kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		row, err := h.editable(r, k, name)
		if err != nil {
			h.fail(w, r, k.what+" "+name, err)
			return
		}
		if !h.validate(w, r, false, runtime.Change{Kind: k.store, Name: name}) {
			return
		}
		if err := h.d.Store.Delete(r.Context(), h.d.Org, k.store, name, row.Version, h.event(r, "delete", k.path+"/"+name)); err != nil {
			h.fail(w, r, k.what+" "+name, err)
			return
		}
		h.reload(r)
		w.WriteHeader(http.StatusNoContent)
	}
}

// mergePatch applies an RFC 7396 merge patch to target.
func mergePatch(target, patch []byte) ([]byte, error) {
	var t, p any
	if len(target) > 0 {
		if err := json.Unmarshal(target, &t); err != nil {
			return nil, err
		}
	}
	if err := decodeAny(patch, &p); err != nil {
		return nil, err
	}
	if _, ok := p.(map[string]any); !ok {
		return nil, invalid("", "a PATCH body must be a JSON object")
	}
	return json.Marshal(merge(t, p))
}

func decodeAny(raw []byte, dst *any) error {
	if err := json.Unmarshal(raw, dst); err != nil {
		var syn *json.SyntaxError
		if errors.As(err, &syn) || len(raw) == 0 {
			return invalid("", "the body is not valid JSON")
		}
		return invalid("", "the body is not valid JSON: %v", err)
	}
	return nil
}

func merge(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
			continue
		}
		t[k] = merge(t[k], v)
	}
	return t
}
