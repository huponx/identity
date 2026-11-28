package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// testService is a namespace of its own, so the tests never touch the real catalog.
func testService(t *testing.T, s *Store) string {
	t.Helper()
	svc := "t" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = s.pool.Exec(ctx, `DELETE FROM identity_role_permissions WHERE permission LIKE $1`, svc+":%")
		_, _ = s.pool.Exec(ctx, `DELETE FROM identity_permissions WHERE service = $1`, svc)
	})
	return svc
}

func testRole(t *testing.T, s *Store, perms ...string) string {
	t.Helper()
	name := "r" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	if err := s.CreateRole(context.Background(), Role{Name: name, Permissions: perms}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM identity_roles WHERE name = $1`, name) })
	return name
}

func defs(names ...string) []PermissionDef {
	var out []PermissionDef
	for _, n := range names {
		out = append(out, PermissionDef{Name: n, Description: "d " + n})
	}
	return out
}

func catalogOf(t *testing.T, s *Store, svc string) map[string]Permission {
	t.Helper()
	list, err := s.ListCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Permission{}
	for _, p := range list {
		if p.Service == svc {
			out[p.Name] = p
		}
	}
	return out
}

func grants(t *testing.T, s *Store, role string) []string {
	t.Helper()
	r, err := s.RoleByName(context.Background(), role)
	if err != nil {
		t.Fatal(err)
	}
	return r.Permissions
}

func TestSyncInsertUpdateDelete(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	svc := testService(t, s)
	a, b, c := svc+":x:read", svc+":x:write", svc+":y:read"

	res, err := s.SyncPermissions(ctx, svc, defs(a, b))
	if err != nil || res.Inserted != 2 {
		t.Fatalf("new: %+v %v", res, err)
	}
	if res, _ = s.SyncPermissions(ctx, svc, defs(a, b)); res.Inserted+res.Updated+res.Deleted+res.Retired != 0 {
		t.Errorf("same set again changes nothing: %+v", res)
	}
	changed := defs(a, c)
	changed[0].Description = "new text"
	res, err = s.SyncPermissions(ctx, svc, changed)
	if err != nil || res.Updated != 1 || res.Inserted != 1 || res.Deleted != 1 || res.Retired != 0 {
		t.Fatalf("description change, insert, delete of the unassigned one: %+v %v", res, err)
	}
	got := catalogOf(t, s, svc)
	if len(got) != 2 || got[a].Description != "new text" || got[c].Service != svc {
		t.Errorf("catalog %+v", got)
	}
	if _, gone := got[b]; gone {
		t.Error("removed and unassigned must be deleted")
	}
}

func TestSyncRemovedButGrantedIsRetiredThenRestored(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	svc := testService(t, s)
	a, b := svc+":x:read", svc+":x:write"
	if _, err := s.SyncPermissions(ctx, svc, defs(a, b)); err != nil {
		t.Fatal(err)
	}
	role := testRole(t, s, a, b, "*")
	u := newTestUser(t, s, role)

	res, err := s.SyncPermissions(ctx, svc, defs(a))
	if err != nil || res.Retired != 1 || res.Deleted != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if !catalogOf(t, s, svc)[b].Retired {
		t.Fatal("b must be retired")
	}
	if g := grants(t, s, role); !reflect.DeepEqual(g, []string{"*", a, b}) {
		t.Errorf("grants must stay: %v", g)
	}
	perms, err := s.UserPermissions(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if contains(perms, b) || !contains(perms, a) || !contains(perms, "*") {
		t.Errorf("the token must lose the retired permission only: %v", perms)
	}
	if active, _ := s.ActivePermissions(ctx); contains(active, b) {
		t.Error("a retired permission is out of the picker")
	}
	// the user keeps the roles
	if roles, _ := s.UserRoles(ctx, u.ID); len(roles) != 1 {
		t.Errorf("roles of the user are never touched: %v", roles)
	}

	// syncing again keeps it retired while a role holds it
	if res, _ = s.SyncPermissions(ctx, svc, defs(a)); res.Retired != 0 || res.Deleted != 0 {
		t.Errorf("second sync: %+v", res)
	}
	// re-added: restored, grants intact
	if res, err = s.SyncPermissions(ctx, svc, defs(a, b)); err != nil || res.Updated != 1 {
		t.Fatalf("restore: %+v %v", res, err)
	}
	if catalogOf(t, s, svc)[b].Retired {
		t.Error("retired_at must be cleared")
	}
	if perms, _ = s.UserPermissions(ctx, u.ID); !contains(perms, b) {
		t.Error("the user holds b again")
	}
}

func TestSyncDeletesARetiredPermissionNobodyHolds(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	svc := testService(t, s)
	a, b := svc+":x:read", svc+":x:write"
	_, _ = s.SyncPermissions(ctx, svc, defs(a, b))
	role := testRole(t, s, b)
	if res, _ := s.SyncPermissions(ctx, svc, defs(a)); res.Retired != 1 {
		t.Fatal("b must be retired")
	}
	if err := s.SetRolePermissions(ctx, role, nil); err != nil { // the administrator removes the retired grant
		t.Fatal(err)
	}
	res, err := s.SyncPermissions(ctx, svc, defs(a))
	if err != nil || res.Deleted != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, ok := catalogOf(t, s, svc)[b]; ok {
		t.Error("b must be deleted")
	}
}

func TestSyncRenameMovesTheGrants(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	svc := testService(t, s)
	old, nw := svc+":x:read", svc+":x:view"
	_, _ = s.SyncPermissions(ctx, svc, defs(old))
	r1, r2 := testRole(t, s, old), testRole(t, s, old, "*")

	d := defs(nw)
	d[0].RenamedFrom = old
	res, err := s.SyncPermissions(ctx, svc, d)
	if err != nil || res.Renamed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if g := grants(t, s, r1); !reflect.DeepEqual(g, []string{nw}) {
		t.Errorf("r1: %v", g)
	}
	if g := grants(t, s, r2); !reflect.DeepEqual(g, []string{"*", nw}) {
		t.Errorf("r2 (the wildcard stays): %v", g)
	}
	if got := catalogOf(t, s, svc); len(got) != 1 || got[nw].Retired {
		t.Errorf("only the new name is left: %+v", got)
	}
	// a second start with the same file changes nothing
	if res, _ = s.SyncPermissions(ctx, svc, d); res.Renamed+res.Inserted+res.Deleted != 0 {
		t.Errorf("idempotent: %+v", res)
	}
}

func TestSyncRefusesAForeignNamespaceAndChangesNothing(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	svc := testService(t, s)
	_, _ = s.SyncPermissions(ctx, svc, defs(svc+":x:read"))
	for _, bad := range [][]PermissionDef{
		defs(svc+":x:read", "dictionary:word:read"),
		defs(svc + ":*:read"),
		defs(svc + ":x"),
		defs(svc+":x:read", svc+":x:read"),
		{{Name: svc + ":x:read", RenamedFrom: "dictionary:word:read"}},
	} {
		if _, err := s.SyncPermissions(ctx, svc, bad); !errors.Is(err, ErrInvalidPermissionDef) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if got := catalogOf(t, s, svc); len(got) != 1 {
		t.Errorf("nothing changed: %+v", got)
	}
	if list, _ := s.ListCatalog(ctx); !hasName(list, "dictionary:word:read") {
		t.Error("the dictionary rows are not touched")
	}
}

func TestSyncFailingMidwayRollsBack(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	svc := testService(t, s)
	a, b, c := svc+":a:read", svc+":b:read", svc+":c:read"
	_, _ = s.SyncPermissions(ctx, svc, defs(a))
	// c exists as a row nobody owns, so the insert of c fails after b was inserted
	if _, err := s.pool.Exec(ctx, `INSERT INTO identity_permissions (permission, service) VALUES ($1, '')`, c); err != nil {
		t.Fatal(err)
	}
	changed := defs(a, b, c)
	changed[0].Description = "other text"
	if _, err := s.SyncPermissions(ctx, svc, changed); err == nil {
		t.Fatal("the unique violation must fail the sync")
	}
	got := catalogOf(t, s, svc)
	if _, ok := got[b]; ok || got[a].Description != "d "+a {
		t.Errorf("all changes or none: %+v", got)
	}
}

func TestSyncNeverTouchesOtherServicesOrWildcardGrants(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	svc, other := testService(t, s), testService(t, s)
	_, _ = s.SyncPermissions(ctx, other, defs(other+":x:read"))
	role := testRole(t, s, "*", "identity:*:read", other+":x:read")
	_, _ = s.SyncPermissions(ctx, svc, defs(svc+":x:read"))
	_, _ = s.SyncPermissions(ctx, svc, nil) // the service now declares nothing
	if got := catalogOf(t, s, other); len(got) != 1 || got[other+":x:read"].Retired {
		t.Errorf("another service that did not report in keeps its permissions: %+v", got)
	}
	if g := grants(t, s, role); len(g) != 3 {
		t.Errorf("grants: %v", g)
	}
}

func TestRetireUnclaimed(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	name := "adhoc" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8] + ":a:b"
	held := "adhoc" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8] + ":a:b"
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM identity_role_permissions WHERE permission = ANY($1)`, []string{name, held})
		_, _ = s.pool.Exec(ctx, `DELETE FROM identity_permissions WHERE permission = ANY($1)`, []string{name, held})
	})
	for _, n := range []string{name, held} {
		if _, err := s.pool.Exec(ctx, `INSERT INTO identity_permissions (permission) VALUES ($1)`, n); err != nil {
			t.Fatal(err)
		}
	}
	role := testRole(t, s, held)
	if _, err := s.RetireUnclaimed(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListCatalog(ctx)
	if hasName(list, name) {
		t.Error("an unclaimed, unheld row is deleted")
	}
	var retired bool
	for _, p := range list {
		if p.Name == held {
			retired = p.Retired
		}
	}
	if !retired || len(grants(t, s, role)) != 1 {
		t.Error("an unclaimed row a role holds is retired, grants kept")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func hasName(list []Permission, name string) bool {
	for _, p := range list {
		if p.Name == name {
			return true
		}
	}
	return false
}
