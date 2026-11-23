package service

import (
	"testing"

	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

// Every RPC of IdentityService has an entry in Permissions and no entry is left over for an RPC that is gone.
// The server is deny by default (grpcserver.WithMethodPermissions), so a missing entry is safe but makes the RPC
// unusable; this test says so at build time instead of on the first call.
func TestEveryRPCHasAPermission(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range identityv1.IdentityService_ServiceDesc.Methods {
		full := "/" + identityv1.IdentityService_ServiceDesc.ServiceName + "/" + m.MethodName
		seen[full] = true
		if Permissions[full] == "" {
			t.Errorf("%s has no entry in Permissions", full)
		}
	}
	for full := range Permissions {
		if !seen[full] {
			t.Errorf("Permissions has %s, which is not an RPC of IdentityService", full)
		}
	}
}
