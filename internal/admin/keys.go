package admin

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
)

// keyName keeps key names fit for the key:<name> subject.
var keyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// keyWrite is a key as the API takes it. The hash and the revoked flag are not part of it.
type keyWrite struct {
	Name      string     `json:"name"`
	Groups    []string   `json:"groups,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func readKeyWrite(raw []byte) (keyWrite, error) {
	var in keyWrite
	if err := decodeStrict(raw, &in); err != nil {
		return in, err
	}
	if !keyName.MatchString(in.Name) {
		return in, invalid("name", "a key name is 1 to 64 letters, digits, dots, dashes or underscores, starting with a letter or digit")
	}
	return in, nil
}

func (k keyWrite) key(sha string, revoked bool) apikey.Key {
	out := apikey.Key{Name: k.Name, SHA256: sha, Groups: k.Groups, Revoked: revoked}
	if k.ExpiresAt != nil {
		out.ExpiresAt = k.ExpiresAt.UTC()
	}
	return out
}

func decodeKeyPatch(raw []byte, prev json.RawMessage) (string, json.RawMessage, error) {
	in, err := readKeyWrite(raw)
	if err != nil {
		return "", nil, err
	}
	var old apikey.Key
	if err := json.Unmarshal(prev, &old); err != nil {
		return "", nil, err
	}
	spec, err := json.Marshal(in.key(old.SHA256, old.Revoked))
	return in.Name, spec, err
}

func keyWriteForm(spec json.RawMessage) (json.RawMessage, error) {
	var k apikey.Key
	if err := json.Unmarshal(spec, &k); err != nil {
		return nil, err
	}
	out := keyWrite{Name: k.Name, Groups: k.Groups}
	if !k.ExpiresAt.IsZero() {
		out.ExpiresAt = &k.ExpiresAt
	}
	return json.Marshal(out)
}

func viewKey(row store.Row) (map[string]any, error) {
	var k apikey.Key
	if err := json.Unmarshal(row.Spec, &k); err != nil {
		return nil, err
	}
	v := map[string]any{"name": k.Name, "revoked": k.Revoked, "expires_at": nil}
	if len(k.Groups) > 0 {
		v["groups"] = k.Groups
	}
	if !k.ExpiresAt.IsZero() {
		v["expires_at"] = formatTime(k.ExpiresAt)
	}
	return v, nil
}

func (h *handler) keyKind() *kind {
	for _, k := range h.kinds() {
		if k.store == store.KindAPIKeys {
			return k
		}
	}
	panic("admin: no api-keys kind")
}

func (h *handler) createKey(w http.ResponseWriter, r *http.Request) {
	raw, err := readBody(w, r)
	if err != nil {
		h.fail(w, r, "API key", err)
		return
	}
	in, err := readKeyWrite(raw)
	if err != nil {
		h.fail(w, r, "API key", err)
		return
	}
	if _, err := h.d.Store.Get(r.Context(), h.d.Org, store.KindAPIKeys, in.Name); err == nil {
		h.fail(w, r, "API key "+in.Name, store.ErrExists)
		return
	}
	plain, sha, err := apikey.Generate()
	if err != nil {
		h.fail(w, r, "API key", err)
		return
	}
	spec, err := json.Marshal(in.key(sha, false))
	if err != nil {
		h.fail(w, r, "API key", err)
		return
	}
	if !h.validate(w, r, true, runtime.Change{Kind: store.KindAPIKeys, Name: in.Name, Spec: spec}) {
		return
	}
	row, err := h.d.Store.Create(r.Context(), h.d.Org, store.KindAPIKeys, in.Name, spec, h.event(r, "create", "api-keys/"+in.Name))
	if err != nil {
		h.fail(w, r, "API key "+in.Name, err)
		return
	}
	h.reload(r)
	v, err := fullView(h.keyKind(), row)
	if err != nil {
		h.fail(w, r, "API key "+in.Name, err)
		return
	}
	v["key"] = plain
	writeVersioned(w, http.StatusCreated, row.Version, v)
}

func (h *handler) revokeKey(w http.ResponseWriter, r *http.Request) {
	k := h.keyKind()
	name := r.PathValue("name")
	row, err := h.editable(r, k, name)
	if err != nil {
		h.fail(w, r, "API key "+name, err)
		return
	}
	var key apikey.Key
	if err := json.Unmarshal(row.Spec, &key); err != nil {
		h.fail(w, r, "API key "+name, err)
		return
	}
	key.Revoked = true
	spec, err := json.Marshal(key)
	if err != nil {
		h.fail(w, r, "API key "+name, err)
		return
	}
	updated, err := h.d.Store.Update(r.Context(), h.d.Org, store.KindAPIKeys, name, row.Version, spec, h.event(r, "revoke", "api-keys/"+name))
	if err != nil {
		h.fail(w, r, "API key "+name, err)
		return
	}
	h.reload(r)
	h.answer(w, r, k, updated, http.StatusOK)
}
