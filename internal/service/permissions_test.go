package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPermissionCatalogMethodsNeedPermissions(t *testing.T) {
	want := map[string]string{
		"ListPermissions":  "identity:permission:read",
		"CreatePermission": "identity:permission:write",
		"UpdatePermission": "identity:permission:write",
		"DeletePermission": "identity:permission:write",
	}
	for m, perm := range want {
		if got := Permissions["/identity.v1.IdentityService/"+m]; got != perm {
			t.Errorf("%s: %q, want %q", m, got, perm)
		}
	}
}

func TestPermissionName(t *testing.T) {
	if permissionName("a:b", "c:d") != "a:b" || permissionName("", "c:d") != "c:d" {
		t.Fatal("the name wins, the gateway path parameter is the fallback")
	}
}

func TestCheckDescription(t *testing.T) {
	if checkDescription(strings.Repeat("x", maxPermissionDescription)) != nil {
		t.Error("the limit itself is fine")
	}
	if checkDescription(strings.Repeat("x", maxPermissionDescription+1)) == nil {
		t.Error("longer must fail")
	}
}

func TestCatalogErrorsMapToCodes(t *testing.T) {
	for err, code := range map[error]codes.Code{
		store.ErrUnknownPermission: codes.InvalidArgument,
		store.ErrPermissionInUse:   codes.FailedPrecondition,
		store.ErrConflict:          codes.AlreadyExists,
	} {
		if got := status.Code(toErr(err)); got != code {
			t.Errorf("%v: %v, want %v", errors.Unwrap(err), got, code)
		}
	}
}

func TestRoleMethodsAndErrors(t *testing.T) {
	for _, m := range []string{"UpdateRole", "DeleteRole"} {
		if got := Permissions["/identity.v1.IdentityService/"+m]; got != "identity:role:write" {
			t.Errorf("%s: %q", m, got)
		}
	}
	if got := status.Code(toErr(store.ErrRoleInUse)); got != codes.FailedPrecondition {
		t.Errorf("role in use: %v", got)
	}
}

func TestClientMethodsAndErrors(t *testing.T) {
	for _, m := range []string{"UpdateClient", "SetClientDisabled", "DeleteClient"} {
		if got := Permissions["/identity.v1.IdentityService/"+m]; got != "identity:client:write" {
			t.Errorf("%s: %q", m, got)
		}
	}
	if got := status.Code(toErr(store.ErrClientNotDisabled)); got != codes.FailedPrecondition {
		t.Errorf("not disabled: %v", got)
	}
}

func TestNormalizeClient(t *testing.T) {
	pub := store.Client{Type: "public", AllowedGrants: []string{"client_credentials"}}
	if normalizeClient(&pub) == nil {
		t.Error("a public client cannot use client_credentials")
	}
	bad := store.Client{Type: "confidential", RedirectURIs: []string{"not a uri"}}
	if normalizeClient(&bad) == nil {
		t.Error("an invalid uri must fail")
	}
	ok := store.Client{Type: "confidential"}
	if err := normalizeClient(&ok); err != nil || len(ok.AllowedGrants) == 0 || len(ok.AllowedScopes) == 0 {
		t.Errorf("defaults: %v %+v", err, ok)
	}
}

func TestSetExchangePolicyDepth(t *testing.T) {
	s := &Service{}
	for _, d := range []int32{-1, 6} {
		_, err := s.SetExchangePolicy(context.Background(), &identityv1.SetExchangePolicyRequest{
			Policy: &identityv1.ExchangePolicy{ClientId: "c", Audience: "a", MaxChainDepth: d},
		})
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Errorf("depth %d: %v", d, got)
		}
	}
}

func TestClientTypeName(t *testing.T) {
	for in, want := range map[identityv1.ClientType]string{
		identityv1.ClientType_CLIENT_TYPE_UNSPECIFIED:  "",
		identityv1.ClientType_CLIENT_TYPE_PUBLIC:       "public",
		identityv1.ClientType_CLIENT_TYPE_CONFIDENTIAL: "confidential",
	} {
		if got := clientTypeName(in); got != want {
			t.Errorf("%v: %q", in, got)
		}
	}
}
