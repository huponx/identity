package service

import (
	"testing"

	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

func TestUserStatusAwaitingApproval(t *testing.T) {
	for _, c := range []struct {
		u    store.User
		want identityv1.UserStatus
	}{
		{store.User{PendingApproval: true}, identityv1.UserStatus_USER_STATUS_PENDING_APPROVAL},
		{store.User{PendingApproval: true, Disabled: true}, identityv1.UserStatus_USER_STATUS_DISABLED},
		{store.User{}, identityv1.UserStatus_USER_STATUS_PENDING},
		{store.User{PasswordHash: "x"}, identityv1.UserStatus_USER_STATUS_ACTIVE},
	} {
		if got := userStatus(&c.u); got != c.want {
			t.Errorf("%+v: %v, want %v", c.u, got, c.want)
		}
	}
	if got := statusFilter(identityv1.UserStatus_USER_STATUS_PENDING_APPROVAL); got != "awaiting_approval" {
		t.Errorf("filter: %+v", got)
	}
}

func TestApprovePermissions(t *testing.T) {
	for _, m := range []string{"ApproveUser", "RejectUser"} {
		if got := Permissions["/identity.v1.IdentityService/"+m]; !ruleIs(got, "identity:user:approve") {
			t.Errorf("%s: %+v", m, got)
		}
	}
}
