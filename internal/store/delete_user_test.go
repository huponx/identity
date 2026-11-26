package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
)

// These tests need the schema of db-migration. Set IDENTITY_TEST_POSTGRES_URL, for example
// postgres://postgres:postgres@localhost:5432/app?sslmode=disable (the database of `make up` in db-migration).
func testPostgres(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("IDENTITY_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("IDENTITY_TEST_POSTGRES_URL is not set")
	}
	s, err := New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func newTestUser(t *testing.T, s *Store, roles ...string) *User {
	t.Helper()
	email := uuid.NewString() + "@identity.test"
	u, err := s.CreateUser(context.Background(), User{Email: email, Name: "Test User", PasswordHash: "hash"}, roles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM identity_users WHERE id = $1`, u.ID) })
	return u
}

func TestDeleteUser(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	role := "test-" + uuid.NewString()
	if err := s.CreateRole(ctx, Role{Name: role}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM identity_roles WHERE name = $1`, role) })
	u := newTestUser(t, s, role)
	if _, err := s.pool.Exec(ctx, `INSERT INTO identity_user_settings (user_id, app, settings) VALUES ($1, 'dictionary', '{}')`, u.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	// every way to find the user skips it
	if _, err := s.UserByID(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByID: %v", err)
	}
	if _, err := s.UserByEmail(ctx, u.Email); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByEmail: %v", err)
	}
	users, _, err := s.ListUsers(ctx, UserFilter{}, "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range users {
		if x.ID == u.ID {
			t.Error("ListUsers returns the deleted user")
		}
	}
	if err := s.SetUserDisabled(ctx, u.ID, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("enable a deleted user: %v", err)
	}
	// the row is anonymized and the small tables are empty
	var email, name string
	var disabled bool
	var hash *string
	if err := s.pool.QueryRow(ctx, `SELECT email, name, disabled, password_hash FROM identity_users WHERE id = $1`, u.ID).Scan(&email, &name, &disabled, &hash); err != nil {
		t.Fatal(err)
	}
	if email != u.ID+"@deleted.invalid" || name != "" || !disabled || hash != nil {
		t.Errorf("row after delete: %q %q %v %v", email, name, disabled, hash)
	}
	for _, tb := range []string{"identity_user_roles", "identity_user_settings", "identity_refresh_tokens", "identity_user_mfa_factors", "identity_password_resets"} {
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM `+tb+` WHERE user_id = $1`, u.ID).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d rows, %v", tb, n, err)
		}
	}
	// the email is free again
	again, err := s.CreateUser(ctx, User{Email: u.Email, Name: "New"}, nil)
	if err != nil {
		t.Fatalf("register the email again: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(context.Background(), `DELETE FROM identity_users WHERE id = $1`, again.ID) })
	// idempotent
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Errorf("second delete: %v", err)
	}
	if err := s.DeleteUser(ctx, uuid.NewString()); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if err := s.DeleteUser(ctx, "not-a-uuid"); !errors.Is(err, ErrNotFound) {
		t.Errorf("bad id: %v", err)
	}
}

func TestDeleteUserLastAdmin(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	var others int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM identity_user_roles r JOIN identity_users u ON u.id = r.user_id
		WHERE r.role = 'admin' AND u.deleted_at IS NULL AND NOT u.disabled`).Scan(&others); err != nil {
		t.Fatal(err)
	}
	a := newTestUser(t, s, "admin")
	if others == 0 {
		// the only admin stays
		if err := s.DeleteUser(ctx, a.ID); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("delete of the last admin: %v", err)
		}
		if _, err := s.UserByID(ctx, a.ID); err != nil {
			t.Fatalf("the last admin is gone: %v", err)
		}
	}
	// with a second admin the first can go; the second is then the last
	b := newTestUser(t, s, "admin")
	if err := s.DeleteUser(ctx, a.ID); err != nil {
		t.Fatalf("delete of one of two admins: %v", err)
	}
	if others == 0 {
		if err := s.DeleteUser(ctx, b.ID); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("delete of the last admin after the first: %v", err)
		}
	}
}

func TestDeleteUserTwoAdminsAtOnce(t *testing.T) {
	ctx := context.Background()
	s := testPostgres(t)
	var others int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM identity_user_roles r JOIN identity_users u ON u.id = r.user_id
		WHERE r.role = 'admin' AND u.deleted_at IS NULL AND NOT u.disabled`).Scan(&others); err != nil {
		t.Fatal(err)
	}
	if others > 0 {
		t.Skip("the database has other admins")
	}
	a, b := newTestUser(t, s, "admin"), newTestUser(t, s, "admin")
	errs := make(chan error, 2)
	for _, id := range []string{a.ID, b.ID} {
		go func() { errs <- s.DeleteUser(ctx, id) }()
	}
	var failed int
	for i := 0; i < 2; i++ {
		if err := <-errs; errors.Is(err, ErrLastAdmin) {
			failed++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if failed != 1 {
		t.Fatalf("%d of two parallel admin deletes were refused, want 1", failed)
	}
}
