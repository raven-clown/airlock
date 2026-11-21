package admin

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/raven-clown/airlock/audit"
	"github.com/raven-clown/airlock/internal/config"
	"github.com/raven-clown/airlock/internal/runtime"
	"github.com/raven-clown/airlock/internal/store"
)

// settingKeys are the top-level keys of config.Settings, each a row in the store.
var settingKeys = []string{"allowed_origins", "public_url", "oidc", "default_profile", "org_profile"}

// settingsView is the settings and their version, which is the sum of the row versions: every
// write raises one row's version, and rows are never deleted through the API, so it only grows.
func (h *handler) settingsView(r *http.Request) (map[string]any, map[string]store.Row, int64, error) {
	rows, err := h.d.Store.List(r.Context(), h.d.Org, store.KindSettings, "", 0)
	if err != nil {
		return nil, nil, 0, err
	}
	byKey := map[string]store.Row{}
	raw := map[string]json.RawMessage{}
	var version int64
	managed := []string{}
	for _, row := range rows {
		byKey[row.Name] = row
		raw[row.Name] = row.Spec
		version += row.Version
		if row.Source == store.SourceFile {
			managed = append(managed, row.Name)
		}
	}
	var s config.Settings
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, nil, 0, err
	}
	b, err = json.Marshal(s)
	if err != nil {
		return nil, nil, 0, err
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, nil, 0, err
	}
	v["version"] = version
	v["managed_by_file"] = len(managed) > 0
	v["managed_keys"] = managed
	return v, byKey, version, nil
}

func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	v, _, version, err := h.settingsView(r)
	if err != nil {
		h.fail(w, r, "settings", err)
		return
	}
	writeVersioned(w, http.StatusOK, version, v)
}

func (h *handler) patchSettings(w http.ResponseWriter, r *http.Request) {
	// Settings that were never written are at version 0, so If-Match may name it.
	want, match, err := ifMatchFrom(r, 0)
	if err != nil {
		h.fail(w, r, "settings", err)
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		h.fail(w, r, "settings", err)
		return
	}
	var patch map[string]json.RawMessage
	if err := json.Unmarshal(body, &patch); err != nil || patch == nil {
		h.fail(w, r, "settings", invalid("", "a PATCH body must be a JSON object"))
		return
	}
	_, rows, version, err := h.settingsView(r)
	if err != nil {
		h.fail(w, r, "settings", err)
		return
	}
	if match && want != version {
		h.fail(w, r, "settings", store.ErrVersionConflict)
		return
	}
	full := map[string]json.RawMessage{}
	for k, row := range rows {
		full[k] = row.Spec
	}
	var changes []runtime.Change
	for _, key := range slices.Sorted(mapKeys(patch)) {
		if !slices.Contains(settingKeys, key) {
			h.fail(w, r, "settings", invalid(key, "unknown setting %s", key))
			return
		}
		row, exists := rows[key]
		if exists && row.Source == store.SourceFile {
			h.fail(w, r, "settings", conflict("managed_by_file", key, "settings.%s is managed by the config file; change it there", key))
			return
		}
		next, err := mergeValue(row.Spec, patch[key])
		if err != nil {
			h.fail(w, r, "settings", err)
			return
		}
		full[key] = next
		changes = append(changes, runtime.Change{Kind: store.KindSettings, Name: key, Spec: next})
	}
	whole, err := json.Marshal(full)
	if err != nil {
		h.fail(w, r, "settings", err)
		return
	}
	var s config.Settings
	if err := decodeStrict(whole, &s); err != nil {
		h.fail(w, r, "settings", err)
		return
	}
	if !h.validate(w, r, true, changes...) {
		return
	}
	puts := make([]store.Put, 0, len(changes))
	events := make([]audit.Event, 0, len(changes))
	for _, c := range changes {
		puts = append(puts, store.Put{Name: c.Name, Version: rows[c.Name].Version, Spec: c.Spec})
		events = append(events, h.event(r, "update", "settings/"+c.Name))
	}
	if err := h.d.Store.PutMany(r.Context(), h.d.Org, store.KindSettings, puts, events...); err != nil {
		h.fail(w, r, "settings", err)
		return
	}
	h.reload(r)
	h.getSettings(w, r)
}

// mergeValue applies an RFC 7396 merge patch to one setting. A null patch clears it.
func mergeValue(current, patch json.RawMessage) (json.RawMessage, error) {
	var t, p any
	if len(current) > 0 {
		if err := json.Unmarshal(current, &t); err != nil {
			return nil, err
		}
	}
	if err := decodeAny(patch, &p); err != nil {
		return nil, err
	}
	return json.Marshal(merge(t, p))
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
