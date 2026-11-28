package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestApprovalFlow(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	email := uuid.NewString() + "@identity.test"
	u, err := s.CreateUser(ctx, User{Email: email, Name: "Applicant", PendingApproval: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM identity_users WHERE id = $1`, u.ID) })
	if !u.PendingApproval {
		t.Fatal("the flag is not stored")
	}

	// listed as awaiting approval, not as pending
	for status, want := range map[string]bool{"awaiting_approval": true, "pending": false} {
		list, _, err := s.ListUsers(ctx, UserFilter{EmailPrefix: email, Status: status}, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if (len(list) == 1) != want {
			t.Errorf("status %s: %d users", status, len(list))
		}
	}

	got, err := s.ApproveUser(ctx, u.ID)
	if err != nil || got.PendingApproval {
		t.Fatalf("ApproveUser: %+v %v", got, err)
	}
	if _, err := s.ApproveUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("approving twice: %v", err)
	}
	if list, _, _ := s.ListUsers(ctx, UserFilter{EmailPrefix: email, Status: "pending"}, "", 10); len(list) != 1 {
		t.Errorf("after approval the user is pending (no password): %d", len(list))
	}

	// rejecting is a soft delete: the address registers again
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.CreateUser(ctx, User{Email: email, PendingApproval: true}, nil)
	if err != nil {
		t.Fatalf("register again: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM identity_users WHERE id = $1`, again.ID) })
}

func TestListUsersWithPermissionAndStats(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	approver := newTestUser(t, s, "user_approver")
	admin := newTestUser(t, s, "admin")
	plain := newTestUser(t, s)
	off := newTestUser(t, s, "user_approver")
	if err := s.SetUserDisabled(ctx, off.ID, true); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListUsersWithPermission(ctx, "identity:user:approve")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, u := range list {
		have[u.ID] = true
	}
	if !have[approver.ID] || !have[admin.ID] || have[plain.ID] || have[off.ID] {
		t.Errorf("approver %v admin %v plain %v disabled %v", have[approver.ID], have[admin.ID], have[plain.ID], have[off.ID])
	}
	if _, err := s.UserStats(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationRequiresApprovalDefault(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	_, _ = s.pool.Exec(ctx, `DELETE FROM identity_system_settings WHERE key = $1`, RegistrationApprovalKey)
	if v, err := s.RegistrationRequiresApproval(ctx); err != nil || !v {
		t.Fatalf("default: %v %v", v, err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(context.Background(), `DELETE FROM identity_system_settings WHERE key = $1`, RegistrationApprovalKey)
	})
	if err := s.PutSystemSettings(ctx, map[string]json.RawMessage{RegistrationApprovalKey: json.RawMessage("false")}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.RegistrationRequiresApproval(ctx); v {
		t.Error("stored false reads as true")
	}
}
