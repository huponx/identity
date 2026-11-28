package service

import (
	"context"
	"testing"

	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPermissionCatalogIsReadOnly(t *testing.T) {
	if got := Permissions["/identity.v1.IdentityService/ListPermissions"]; !ruleIs(got, "identity:permission:read") {
		t.Errorf("ListPermissions: %+v", got)
	}
	if got := Permissions["/identity.v1.IdentityService/RegisterPermissions"]; !ruleIs(got, "identity:permission:register") {
		t.Errorf("RegisterPermissions: %+v", got)
	}
	for _, m := range []string{"CreatePermission", "UpdatePermission", "DeletePermission"} {
		if _, ok := Permissions["/identity.v1.IdentityService/"+m]; ok {
			t.Errorf("%s must be gone: administrators only read the catalog", m)
		}
	}
}

func TestDescribeWildcard(t *testing.T) {
	for w, want := range map[string]string{
		"*": "Everything, in every service", "identity:*": "Everything in identity",
		"identity:*:read": "Every read permission in identity", "identity:user:*": "Every permission on user in identity",
	} {
		if got := describeWildcard(w); got != want {
			t.Errorf("%s: %+v", w, got)
		}
	}
}

func TestCatalogErrorsMapToCodes(t *testing.T) {
	for err, code := range map[error]codes.Code{
		store.ErrUnknownPermission:    codes.InvalidArgument,
		store.ErrInvalidPermissionDef: codes.InvalidArgument,
		store.ErrConflict:             codes.AlreadyExists,
	} {
		if got := status.Code(toErr(err)); got != code {
			t.Errorf("%v: %v, want %v", err, got, code)
		}
	}
}

func TestRoleMethodsAndErrors(t *testing.T) {
	for _, m := range []string{"UpdateRole", "DeleteRole"} {
		if got := Permissions["/identity.v1.IdentityService/"+m]; !ruleIs(got, "identity:role:write") {
			t.Errorf("%s: %+v", m, got)
		}
	}
	if got := status.Code(toErr(store.ErrRoleInUse)); got != codes.FailedPrecondition {
		t.Errorf("role in use: %v", got)
	}
}

func TestClientMethodsAndErrors(t *testing.T) {
	for _, m := range []string{"UpdateClient", "SetClientDisabled", "DeleteClient"} {
		if got := Permissions["/identity.v1.IdentityService/"+m]; !ruleIs(got, "identity:client:write") {
			t.Errorf("%s: %+v", m, got)
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
			t.Errorf("%v: %+v", in, got)
		}
	}
}
