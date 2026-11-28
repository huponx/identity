package service

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testService(t *testing.T) *Service {
	t.Helper()
	url := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("IDENTITY_TEST_POSTGRES_URL is not set")
	}
	st, err := store.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := SyncOwnPermissions(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	return &Service{Store: st}
}

func uniq(prefix string) string {
	return prefix + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
}

func TestOwnSyncPutsTheDeclaredPermissionsInTheCatalog(t *testing.T) {
	s := testService(t)
	list, err := s.Store.ListCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]store.Permission{}
	for _, p := range list {
		have[p.Name] = p
	}
	for _, want := range []string{"identity:user:read", "identity:permission:register", "bill:invoice:read", "system:status:read"} {
		if p, ok := have[want]; !ok || p.Retired || p.Description == "" {
			t.Errorf("%s: %+v", want, p)
		}
	}
	for name := range have {
		if strings.Contains(name, "*") {
			t.Errorf("wildcards are not rows: %s", name)
		}
	}
	if _, ok := have["identity:permission:write"]; ok {
		t.Error("the catalog write permission is gone")
	}
}

func TestSetRolePermissionsAcceptsWildcardsAndRejectsOthers(t *testing.T) {
	ctx := context.Background()
	s := testService(t)
	role := uniq("r")
	if _, err := s.CreateRole(ctx, &identityv1.CreateRoleRequest{Role: &identityv1.Role{Name: role}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.DeleteRole(ctx, &identityv1.DeleteRoleRequest{Role: role}) })

	set := func(p ...string) error {
		_, err := s.SetRolePermissions(ctx, &identityv1.SetRolePermissionsRequest{Role: role, Permissions: p})
		return err
	}
	for _, ok := range []string{"*", "identity:*", "identity:*:read", "identity:user:*", "identity:user:read", "dictionary:*:write"} {
		if err := set(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"identity:*:purge", "foo", "identity:user:purge", "nosuch:*"} {
		err := set(bad)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestRetiredGrantIsListedKeptAndRemovable(t *testing.T) {
	ctx := context.Background()
	s := testService(t)
	svc := uniq("t")
	keep, gone := svc+":x:read", svc+":x:write"
	register := func(names ...string) {
		req := &identityv1.RegisterPermissionsRequest{Service: svc}
		for _, n := range names {
			req.Permissions = append(req.Permissions, &identityv1.PermissionDeclaration{Name: n, Description: "d"})
		}
		if _, err := s.RegisterPermissions(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	register(keep, gone)
	role := uniq("r")
	if _, err := s.CreateRole(ctx, &identityv1.CreateRoleRequest{Role: &identityv1.Role{Name: role, Permissions: []string{keep, gone, svc + ":*"}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.DeleteRole(ctx, &identityv1.DeleteRoleRequest{Role: role})
		_, _ = s.Store.SyncPermissions(ctx, svc, nil)
	})

	register(keep)
	list, err := s.ListRoles(ctx, &identityv1.ListRolesRequest{Query: role})
	if err != nil || len(list.Roles) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	r := list.Roles[0]
	if len(r.Permissions) != 3 || len(r.RetiredPermissions) != 1 || r.RetiredPermissions[0] != gone {
		t.Errorf("the role keeps the grant and marks it retired: %+v", r)
	}
	// saving the role with the retired grant still in it works; the picker never offers it
	if _, err := s.SetRolePermissions(ctx, &identityv1.SetRolePermissionsRequest{Role: role, Permissions: r.Permissions}); err != nil {
		t.Errorf("keep the retired grant: %v", err)
	}
	perms, err := s.ListPermissions(ctx, &identityv1.ListPermissionsRequest{Query: svc})
	if err != nil {
		t.Fatal(err)
	}
	retired := 0
	for _, p := range perms.Permissions {
		if p.Retired && p.Name == gone {
			retired++
		}
	}
	if retired != 1 {
		t.Errorf("ListPermissions flags it retired: %+v", perms.Permissions)
	}
	// removing it
	out, err := s.SetRolePermissions(ctx, &identityv1.SetRolePermissionsRequest{Role: role, Permissions: []string{keep, svc + ":*"}})
	if err != nil || len(out.Role.RetiredPermissions) != 0 {
		t.Errorf("remove: %+v %v", out, err)
	}
	// adding it back by hand is refused, it is not declared
	if _, err := s.SetRolePermissions(ctx, &identityv1.SetRolePermissionsRequest{Role: role, Permissions: []string{keep, gone}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("retired is not grantable: %v", err)
	}
}

func TestStaleWildcardIsKeptAsRetired(t *testing.T) {
	ctx := context.Background()
	s := testService(t)
	role := uniq("r")
	st := s.Store
	if err := st.CreateRole(ctx, store.Role{Name: role, Permissions: []string{"gone" + "svc:*", "*"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.DeleteRole(ctx, &identityv1.DeleteRoleRequest{Role: role}) })
	r, err := s.ListRoles(ctx, &identityv1.ListRolesRequest{Query: role})
	if err != nil || len(r.Roles) != 1 {
		t.Fatal(err)
	}
	if got := r.Roles[0].RetiredPermissions; len(got) != 1 || got[0] != "gonesvc:*" {
		t.Errorf("a wildcard that covers nothing is shown as retired, * never: %v", got)
	}
}

func TestListPermissionsMixesWildcards(t *testing.T) {
	s := testService(t)
	out, err := s.ListPermissions(context.Background(), &identityv1.ListPermissionsRequest{Query: "identity", PageSize: 200})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]*identityv1.Permission{}
	for _, p := range out.Permissions {
		seen[p.Name] = p
	}
	if p := seen["identity:*:read"]; p == nil || !p.Wildcard || p.Service != "" {
		t.Errorf("identity:*:read: %+v", p)
	}
	if p := seen["identity:user:read"]; p == nil || p.Wildcard || p.Service != "identity" {
		t.Errorf("identity:user:read: %+v", p)
	}
	all, _ := s.ListPermissions(context.Background(), &identityv1.ListPermissionsRequest{PageSize: 200})
	found := false
	for _, p := range all.Permissions {
		if p.Name == "*" && p.Wildcard {
			found = true
		}
	}
	if !found {
		t.Error("* is listed")
	}
	page, _ := s.ListPermissions(context.Background(), &identityv1.ListPermissionsRequest{PageSize: 3})
	if len(page.Permissions) != 3 || page.NextPageToken == "" || page.Total <= 3 {
		t.Errorf("paging: %+v", page)
	}
}

func TestRegisterPermissionsNamespaceRules(t *testing.T) {
	ctx := context.Background()
	s := testService(t)
	svc := uniq("t")
	t.Cleanup(func() { _, _ = s.Store.SyncPermissions(context.Background(), svc, nil) })
	good := &identityv1.RegisterPermissionsRequest{Service: svc, Permissions: []*identityv1.PermissionDeclaration{{Name: svc + ":a:read", Description: "d"}}}

	// a trusted in-cluster caller (no token) may register its namespace
	res, err := s.RegisterPermissions(ctx, good)
	if err != nil || res.Inserted != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	// a name outside the namespace is refused
	bad := &identityv1.RegisterPermissionsRequest{Service: svc, Permissions: []*identityv1.PermissionDeclaration{{Name: "dictionary:word:read"}}}
	if _, err := s.RegisterPermissions(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Errorf("foreign name: %v", err)
	}
	// identity, bill and system are synced by identity itself
	for _, reserved := range []string{"identity", "bill", "system"} {
		if _, err := s.RegisterPermissions(ctx, &identityv1.RegisterPermissionsRequest{Service: reserved}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v", reserved, err)
		}
	}
	// a token whose subject is not a client of that service is refused
	other := authn.WithPrincipal(ctx, &authn.Principal{Subject: uuid.NewString()})
	if _, err := s.RegisterPermissions(other, good); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a user token: %v", err)
	}
	// a client whose resource is another service is refused; the matching one passes
	cid := uniq("c")
	if _, err := s.Store.CreateClient(ctx, store.Client{ClientID: cid, Name: cid, Type: "confidential", SecretHash: "x", Resource: svc, AllowedGrants: []string{"client_credentials"}, AllowedScopes: []string{}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.Store.SetClientDisabled(context.Background(), cid, true)
		_ = s.Store.DeleteClient(context.Background(), cid)
	})
	asClient := authn.WithPrincipal(ctx, &authn.Principal{Subject: cid, ClientID: cid})
	if _, err := s.RegisterPermissions(asClient, good); err != nil {
		t.Errorf("own client: %v", err)
	}
	wrong := &identityv1.RegisterPermissionsRequest{Service: uniq("x")}
	if _, err := s.RegisterPermissions(asClient, wrong); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a client registering another service: %v", err)
	}
}
