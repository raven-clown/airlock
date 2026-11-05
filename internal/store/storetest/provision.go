package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/raven-clown/airlock/internal/store"
)

var provisionTests = []subtest{
	{"ProvisionAddChangeRemove", testProvisionAddChangeRemove},
	{"ProvisionUnchanged", testProvisionUnchanged},
	{"ProvisionNameTaken", testProvisionNameTaken},
	{"ProvisionConcurrent", testProvisionConcurrent},
	{"ManagedByFile", testManagedByFile},
	{"ProvisionEmpty", testProvisionEmpty},
}

type fileRows = map[store.Kind]map[string]json.RawMessage

func servers(kv ...string) fileRows {
	m := map[string]json.RawMessage{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = spec(kv[i+1])
	}
	return fileRows{store.KindServers: m}
}

func provision(t *testing.T, st *store.Store, org string, want fileRows) bool {
	t.Helper()
	changed, err := st.Provision(context.Background(), org, want)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func testProvisionAddChangeRemove(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	mustCreate(t, st, org, store.KindServers, "api", "mine")
	if !provision(t, st, org, servers("a", "one", "b", "one")) {
		t.Error("first provision reported no change")
	}
	if !provision(t, st, org, servers("a", "two")) {
		t.Error("second provision reported no change")
	}
	rows, err := st.List(ctx, org, store.KindServers, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(rows)); got != "[a api]" {
		t.Fatalf("rows = %s, want [a api]", got)
	}
	a := rows[0]
	if a.Source != store.SourceFile || a.Version != 2 || specValue(t, a.Spec) != "two" {
		t.Errorf("a = %+v", a)
	}
	if api := rows[1]; api.Source != store.SourceAPI || specValue(t, api.Spec) != "mine" {
		t.Errorf("api row changed: %+v", api)
	}
}

func testProvisionUnchanged(t *testing.T, st *store.Store, org string) {
	provision(t, st, org, servers("a", "one"))
	before := revision(t, st, org)
	if provision(t, st, org, servers("a", "one")) {
		t.Error("unchanged input reported a change")
	}
	if after := revision(t, st, org); after != before {
		t.Errorf("revision moved from %d to %d", before, after)
	}
}

func testProvisionNameTaken(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	mustCreate(t, st, org, store.KindServers, "github", "api")
	before := revision(t, st, org)
	want := servers("github", "file")
	want[store.KindRules] = map[string]json.RawMessage{"r1": spec("rule")}
	_, err := st.Provision(ctx, org, want)
	var taken *store.NameTakenError
	if !errors.As(err, &taken) || taken.Kind != store.KindServers || taken.Name != "github" {
		t.Fatalf("Provision error = %v, want NameTakenError for servers github", err)
	}
	if _, err := st.Get(ctx, org, store.KindRules, "r1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("rule r1 written despite the failure: %v", err)
	}
	if after := revision(t, st, org); after != before {
		t.Errorf("revision moved from %d to %d", before, after)
	}
}

func testProvisionConcurrent(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	before := revision(t, st, org)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := st.Provision(ctx, org, servers("a", "one", "b", "two"))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Provision: %v", err)
		}
	}
	rows, err := st.List(ctx, org, store.KindServers, "", 0)
	if err != nil || fmt.Sprint(names(rows)) != "[a b]" {
		t.Errorf("rows = %v, %v", names(rows), err)
	}
	if after := revision(t, st, org); after != before+1 {
		t.Errorf("revision moved from %d to %d, want one step", before, after)
	}
}

func testManagedByFile(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	provision(t, st, org, servers("a", "one"))
	if _, err := st.Update(ctx, org, store.KindServers, "a", 1, spec("two")); !errors.Is(err, store.ErrManagedByFile) {
		t.Errorf("Update error = %v, want ErrManagedByFile", err)
	}
	if err := st.Delete(ctx, org, store.KindServers, "a", 1); !errors.Is(err, store.ErrManagedByFile) {
		t.Errorf("Delete error = %v, want ErrManagedByFile", err)
	}
	if _, err := st.Create(ctx, org, store.KindServers, "a", spec("two")); !errors.Is(err, store.ErrExists) {
		t.Errorf("Create error = %v, want ErrExists", err)
	}
}

func testProvisionEmpty(t *testing.T, st *store.Store, org string) {
	ctx := context.Background()
	want := fileRows{}
	for _, k := range store.Kinds {
		want[k] = map[string]json.RawMessage{"file-" + string(k): spec("f")}
		mustCreate(t, st, org, k, "api-"+string(k), "a")
	}
	provision(t, st, org, want)
	if !provision(t, st, org, fileRows{}) {
		t.Error("removing every file row reported no change")
	}
	for _, k := range store.Kinds {
		rows, err := st.List(ctx, org, k, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(names(rows)); got != "[api-"+string(k)+"]" {
			t.Errorf("%s rows = %s", k, got)
		}
	}
}
