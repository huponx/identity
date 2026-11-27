package service

import (
	"testing"

	"github.com/huponx/gocommon/grpcserver"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

// ruleIs reports whether the rule is "the caller needs this one permission".
func ruleIs(got grpcserver.Rule, perm string) bool {
	return len(got.Any) == 1 && got.Any[0] == perm && len(got.All) == 0 && !got.Public
}

// Every RPC of IdentityService has exactly one rule and every name in them is declared in permissions.proto.
// The server is deny by default (grpcserver.WithMethodPermissions), so a missing rule is safe but makes the RPC
// unusable; this test says so at build time instead of on the first call.
func TestCoverage(t *testing.T) {
	grpcserver.CheckCoverage(t, identityv1.File_identity_v1_identity_proto, identityv1.File_identity_v1_permissions_proto)
	for _, m := range identityv1.IdentityService_ServiceDesc.Methods {
		full := "/" + identityv1.IdentityService_ServiceDesc.ServiceName + "/" + m.MethodName
		if _, ok := Permissions[full]; !ok {
			t.Errorf("%s is not in Permissions", full)
		}
	}
}

func TestListUsersAcceptsAnApprover(t *testing.T) {
	r := Permissions["/identity.v1.IdentityService/ListUsers"]
	if !r.Allows([]string{"identity:user:approve"}) || !r.Allows([]string{"identity:user:read"}) || r.Allows([]string{"identity:user:write"}) {
		t.Errorf("ListUsers rule %+v", r)
	}
}
