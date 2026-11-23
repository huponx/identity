// Package store is the PostgreSQL access of identity. The schema lives in the db-migration
// repository (identity_* tables).
package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: already exists")
	// ErrUnknownPermission: a role was given a permission that is not in the catalog.
	ErrUnknownPermission = errors.New("store: permission is not in the catalog")
	// ErrPermissionInUse: the permission is held by a role and cannot be deleted.
	ErrPermissionInUse = errors.New("store: permission is held by a role")
	// ErrRoleInUse: the role is held by a user or a client and cannot be deleted.
	ErrRoleInUse = errors.New("store: role is held by a user or a client")
	// ErrClientNotDisabled: only a disabled client can be deleted.
	ErrClientNotDisabled = errors.New("store: client is not disabled")
)

// Store wraps the pool.
type Store struct {
	pool *pgxpool.Pool
}

// New connects and pings.
func New(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Ping is the readiness check.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505": // unique_violation
			return ErrConflict
		case "23503": // foreign_key_violation: the referenced row does not exist
			if pg.ConstraintName == "identity_role_permissions_permission_fkey" {
				return ErrUnknownPermission
			}
			return ErrNotFound
		}
	}
	return err
}

// ---- users ----

// User is a row of identity_users.
type User struct {
	ID                string
	Email             string
	Name              string
	Locale            string
	PasswordHash      string // "" when none is set
	PasswordChangedAt *time.Time
	Disabled          bool
	MFAEnabled        bool
	MFAEnforced       bool
	// MustChangePassword: the password was set by somebody else (setup Job); the user must choose their own at the next sign in.
	MustChangePassword bool
	CreatedAt          time.Time
	HasAvatar          bool       // the picture itself is read with UserAvatar
	LastLoginAt        *time.Time // nil: never signed in (or before sign ins were tracked)
	Theme              string     // light, dark or system; "" until the user chose one
}

const userCols = `id::text, email, name, locale, coalesce(password_hash, ''), password_changed_at, disabled, mfa_enabled, mfa_enforced, must_change_password, created_at, avatar IS NOT NULL, last_login_at, coalesce(theme, '')`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Locale, &u.PasswordHash, &u.PasswordChangedAt, &u.Disabled, &u.MFAEnabled, &u.MFAEnforced, &u.MustChangePassword, &u.CreatedAt, &u.HasAvatar, &u.LastLoginAt, &u.Theme)
	if err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

// NormalizeEmail is the form stored: trimmed and lower case.
func NormalizeEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// CreateUser inserts a user and its roles in one transaction.
func (s *Store) CreateUser(ctx context.Context, u User, roles []string) (*User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if u.Locale == "" {
		u.Locale = "en"
	}
	var pw any
	var changed any
	if u.PasswordHash != "" {
		pw, changed = u.PasswordHash, time.Now()
	}
	row := tx.QueryRow(ctx, `INSERT INTO identity_users (email, name, locale, password_hash, password_changed_at, must_change_password)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+userCols, NormalizeEmail(u.Email), u.Name, u.Locale, pw, changed, u.MustChangePassword)
	created, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_user_roles (user_id, role) VALUES ($1, $2)`, created.ID, r); err != nil {
			return nil, mapErr(err)
		}
	}
	return created, tx.Commit(ctx)
}

// UserByID returns the user.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, ErrNotFound
	}
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM identity_users WHERE id = $1`, id))
}

// UserByEmail returns the user.
func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM identity_users WHERE email = $1`, NormalizeEmail(email)))
}

func (s *Store) execUser(ctx context.Context, id, sql string, args ...any) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, sql, append([]any{id}, args...)...)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserDisabled enables or disables the account.
func (s *Store) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	return s.execUser(ctx, id, `UPDATE identity_users SET disabled = $2, updated_at = now() WHERE id = $1`, disabled)
}

// UpdateUser changes the name and, when locale is not empty, the locale.
func (s *Store) UpdateUser(ctx context.Context, id, name, locale string) error {
	return s.execUser(ctx, id, `UPDATE identity_users SET name = $2, locale = coalesce(nullif($3, ''), locale), updated_at = now() WHERE id = $1`, name, locale)
}

// SetUserTheme stores the theme the user chose (light, dark or system; the caller validates it).
func (s *Store) SetUserTheme(ctx context.Context, id, theme string) error {
	return s.execUser(ctx, id, `UPDATE identity_users SET theme = $2, updated_at = now() WHERE id = $1`, theme)
}

// SetUserAvatar stores the encoded picture; an empty image removes it.
func (s *Store) SetUserAvatar(ctx context.Context, id string, image []byte, mime string) error {
	if len(image) == 0 {
		return s.execUser(ctx, id, `UPDATE identity_users SET avatar = NULL, avatar_mime = NULL, updated_at = now() WHERE id = $1`)
	}
	return s.execUser(ctx, id, `UPDATE identity_users SET avatar = $2, avatar_mime = $3, updated_at = now() WHERE id = $1`, image, mime)
}

// UserAvatar returns the picture and its media type; ErrNotFound when the user has none.
func (s *Store) UserAvatar(ctx context.Context, id string) ([]byte, string, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, "", ErrNotFound
	}
	var img []byte
	var mime *string
	if err := s.pool.QueryRow(ctx, `SELECT avatar, avatar_mime FROM identity_users WHERE id = $1`, id).Scan(&img, &mime); err != nil {
		return nil, "", mapErr(err)
	}
	if img == nil || mime == nil {
		return nil, "", ErrNotFound
	}
	return img, *mime, nil
}

// SetUserPassword stores a new password hash.
func (s *Store) SetUserPassword(ctx context.Context, id, hash string) error {
	return s.execUser(ctx, id, `UPDATE identity_users SET password_hash = $2, password_changed_at = now(), must_change_password = false, updated_at = now() WHERE id = $1`, hash)
}

// SetUserMFAFlags updates mfa_enabled and mfa_enforced (nil leaves a flag alone).
func (s *Store) SetUserMFAFlags(ctx context.Context, id string, enabled, enforced *bool) error {
	return s.execUser(ctx, id, `UPDATE identity_users SET
		mfa_enabled = coalesce($2, mfa_enabled), mfa_enforced = coalesce($3, mfa_enforced), updated_at = now() WHERE id = $1`, enabled, enforced)
}

// UserRoles lists the roles of a user.
func (s *Store) UserRoles(ctx context.Context, id string) ([]string, error) {
	return s.strings(ctx, `SELECT role FROM identity_user_roles WHERE user_id = $1 ORDER BY role`, id)
}

// UserPermissions is the union of the permissions of the roles of a user.
func (s *Store) UserPermissions(ctx context.Context, id string) ([]string, error) {
	return s.strings(ctx, `SELECT DISTINCT p.permission FROM identity_user_roles ur
		JOIN identity_role_permissions p ON p.role = ur.role WHERE ur.user_id = $1 ORDER BY 1`, id)
}

func (s *Store) strings(ctx context.Context, sql string, args ...any) ([]string, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// CreateFirstAdmin creates the user with the admin role only when no admin exists. The check and the
// insert run in one transaction under an advisory lock, so two concurrent runs create at most one admin.
// It returns nil, false when an admin already exists.
func (s *Store) CreateFirstAdmin(ctx context.Context, u User) (*User, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('identity-first-admin'))`); err != nil {
		return nil, false, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_user_roles WHERE role = 'admin'`).Scan(&n); err != nil {
		return nil, false, err
	}
	if n > 0 {
		return nil, false, nil
	}
	if u.Locale == "" {
		u.Locale = "en"
	}
	row := tx.QueryRow(ctx, `INSERT INTO identity_users (email, name, locale, password_hash, password_changed_at, must_change_password)
		VALUES ($1, $2, $3, $4, now(), $5) RETURNING `+userCols, NormalizeEmail(u.Email), u.Name, u.Locale, u.PasswordHash, u.MustChangePassword)
	created, err := scanUser(row)
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_user_roles (user_id, role) VALUES ($1, 'admin')`, created.ID); err != nil {
		return nil, false, mapErr(err)
	}
	return created, true, tx.Commit(ctx)
}

// CountAdmins is the number of users holding the admin role (bootstrap runs only at zero).
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM identity_user_roles WHERE role = 'admin'`).Scan(&n)
	return n, err
}

// ---- clients ----

// Client is a row of identity_clients.
type Client struct {
	ClientID               string
	Name                   string
	Type                   string // public, confidential
	SecretHash             string // hex sha256, "" for public
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   string
	AllowedGrants          []string
	AllowedScopes          []string
	Resource               string
	AccessTokenTTL         time.Duration // 0: server default
	Disabled               bool
	Roles                  []string
}

const clientCols = `client_id, name, type, coalesce(secret_hash, ''), redirect_uris, post_logout_redirect_uris, backchannel_logout_uri,
	allowed_grants, allowed_scopes, resource, coalesce(access_token_ttl_seconds, 0), disabled,
	coalesce((SELECT array_agg(role ORDER BY role) FROM identity_client_roles cr WHERE cr.client_id = identity_clients.client_id), '{}')`

func scanClient(row pgx.Row) (*Client, error) {
	var c Client
	var ttl int
	err := row.Scan(&c.ClientID, &c.Name, &c.Type, &c.SecretHash, &c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.BackchannelLogoutURI,
		&c.AllowedGrants, &c.AllowedScopes, &c.Resource, &ttl, &c.Disabled, &c.Roles)
	if err != nil {
		return nil, mapErr(err)
	}
	c.AccessTokenTTL = time.Duration(ttl) * time.Second
	return &c, nil
}

// CreateClient inserts a client and its roles.
func (s *Store) CreateClient(ctx context.Context, c Client) (*Client, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var secret any
	if c.SecretHash != "" {
		secret = c.SecretHash
	}
	_, err = tx.Exec(ctx, `INSERT INTO identity_clients (client_id, name, type, secret_hash, redirect_uris, post_logout_redirect_uris,
		backchannel_logout_uri, allowed_grants, allowed_scopes, resource) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.ClientID, c.Name, c.Type, secret, nz(c.RedirectURIs), nz(c.PostLogoutRedirectURIs), c.BackchannelLogoutURI,
		nz(c.AllowedGrants), nz(c.AllowedScopes), c.Resource)
	if err != nil {
		return nil, mapErr(err)
	}
	for _, r := range c.Roles {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_client_roles (client_id, role) VALUES ($1, $2)`, c.ClientID, r); err != nil {
			return nil, mapErr(err)
		}
	}
	out, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientCols+` FROM identity_clients WHERE client_id = $1`, c.ClientID))
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ClientByID returns the client.
func (s *Store) ClientByID(ctx context.Context, id string) (*Client, error) {
	return scanClient(s.pool.QueryRow(ctx, `SELECT `+clientCols+` FROM identity_clients WHERE client_id = $1`, id))
}

// ListClients returns the clients; a query keeps those whose id, name or type contains it (case insensitive) or
// that have a grant or a role containing it; clientType ("public" or "confidential", empty for both) narrows further.
// Up to limit+1 clients come back, ordered by id and starting after the id `after` ("" for the first page), so the
// caller can tell whether another page exists.
func (s *Store) ListClients(ctx context.Context, query, clientType, after string, limit int) ([]Client, error) {
	like := ""
	if query != "" {
		like = likeContains(query)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+clientCols+` FROM identity_clients
		WHERE ($1 = '' OR client_id ILIKE $1 OR name ILIKE $1 OR type ILIKE $1
		   OR EXISTS (SELECT 1 FROM unnest(allowed_grants) g WHERE g ILIKE $1)
		   OR EXISTS (SELECT 1 FROM identity_client_roles cr WHERE cr.client_id = identity_clients.client_id AND cr.role ILIKE $1))
		  AND ($2 = '' OR type = $2)
		  AND client_id > $3
		ORDER BY client_id LIMIT $4`, like, clientType, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// UpdateClient replaces everything of a client but its id, type and secret, roles included.
func (s *Store) UpdateClient(ctx context.Context, c Client) (*Client, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE identity_clients SET name = $2, redirect_uris = $3, post_logout_redirect_uris = $4,
		backchannel_logout_uri = $5, allowed_grants = $6, allowed_scopes = $7, resource = $8, updated_at = now() WHERE client_id = $1`,
		c.ClientID, c.Name, nz(c.RedirectURIs), nz(c.PostLogoutRedirectURIs), c.BackchannelLogoutURI, nz(c.AllowedGrants), nz(c.AllowedScopes), c.Resource)
	if err != nil {
		return nil, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_client_roles WHERE client_id = $1`, c.ClientID); err != nil {
		return nil, err
	}
	for _, r := range c.Roles {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_client_roles (client_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`, c.ClientID, r); err != nil {
			return nil, mapErr(err)
		}
	}
	out, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientCols+` FROM identity_clients WHERE client_id = $1`, c.ClientID))
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// SetClientDisabled disables or enables a client.
func (s *Store) SetClientDisabled(ctx context.Context, id string, disabled bool) (*Client, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_clients SET disabled = $2, updated_at = now() WHERE client_id = $1`, id, disabled)
	if err != nil {
		return nil, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.ClientByID(ctx, id)
}

// DeleteClient removes a disabled client; its roles and exchange policies cascade. The row is locked while
// the flag is read, so a concurrent enable cannot slip in.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var disabled bool
	if err := tx.QueryRow(ctx, `SELECT disabled FROM identity_clients WHERE client_id = $1 FOR UPDATE`, id).Scan(&disabled); err != nil {
		return mapErr(err)
	}
	if !disabled {
		return ErrClientNotDisabled
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_clients WHERE client_id = $1`, id); err != nil {
		return mapErr(err)
	}
	return tx.Commit(ctx)
}

// SetClientSecret replaces the secret hash of a confidential client.
func (s *Store) SetClientSecret(ctx context.Context, id, hash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_clients SET secret_hash = $2, updated_at = now() WHERE client_id = $1 AND type = 'confidential'`, id, hash)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetClientConfig replaces the URIs, grants and scopes of an existing client (the setup Job passes the
// union of the stored and the wanted values).
func (s *Store) SetClientConfig(ctx context.Context, id string, redirects, logouts, grants, scopes []string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_clients SET redirect_uris = $2, post_logout_redirect_uris = $3,
		allowed_grants = $4, allowed_scopes = $5, updated_at = now() WHERE client_id = $1`,
		id, nz(redirects), nz(logouts), nz(grants), nz(scopes))
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClientPermissions is the union of the permissions of the roles of a client.
func (s *Store) ClientPermissions(ctx context.Context, id string) ([]string, error) {
	return s.strings(ctx, `SELECT DISTINCT p.permission FROM identity_client_roles cr
		JOIN identity_role_permissions p ON p.role = cr.role WHERE cr.client_id = $1 ORDER BY 1`, id)
}

// ---- roles ----

// Role is a role with its permissions.
type Role struct {
	Name        string
	Description string
	Permissions []string
	// AssignedCount is how many users and clients hold the role (read by ListRoles and RoleByName).
	AssignedCount int64
}

// CreateRole inserts a role and its permissions.
func (s *Store) CreateRole(ctx context.Context, r Role) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `INSERT INTO identity_roles (name, description) VALUES ($1, $2)`, r.Name, r.Description); err != nil {
		return mapErr(err)
	}
	for _, p := range r.Permissions {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_role_permissions (role, permission) VALUES ($1, $2) ON CONFLICT DO NOTHING`, r.Name, p); err != nil {
			return mapErr(err)
		}
	}
	return tx.Commit(ctx)
}

// SetRolePermissions replaces the permissions of a role.
func (s *Store) SetRolePermissions(ctx context.Context, role string, perms []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM identity_roles WHERE name = $1 FOR UPDATE`, role).Scan(&exists); err != nil {
		return mapErr(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_role_permissions WHERE role = $1`, role); err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_role_permissions (role, permission) VALUES ($1, $2) ON CONFLICT DO NOTHING`, role, p); err != nil {
			return mapErr(err)
		}
	}
	return tx.Commit(ctx)
}

// UpdateRole replaces the description and the permissions of a role.
func (s *Store) UpdateRole(ctx context.Context, name, description string, perms []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE identity_roles SET description = $2 WHERE name = $1`, name, description)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_role_permissions WHERE role = $1`, name); err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_role_permissions (role, permission) VALUES ($1, $2) ON CONFLICT DO NOTHING`, name, p); err != nil {
			return mapErr(err)
		}
	}
	return tx.Commit(ctx)
}

// DeleteRole removes a role that no user and no client holds (ErrRoleInUse otherwise, ErrNotFound when
// it does not exist). The role row is locked, so a concurrent AssignRole cannot slip in.
func (s *Store) DeleteRole(ctx context.Context, name string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var held int64
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_user_roles WHERE role = r.name)
		+ (SELECT count(*) FROM identity_client_roles WHERE role = r.name) FROM identity_roles r WHERE r.name = $1 FOR UPDATE`, name).Scan(&held); err != nil {
		return mapErr(err)
	}
	if held > 0 {
		return ErrRoleInUse
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_roles WHERE name = $1`, name); err != nil {
		return mapErr(err)
	}
	return tx.Commit(ctx)
}

const assignedCount = `(SELECT count(*) FROM identity_user_roles WHERE role = r.name) + (SELECT count(*) FROM identity_client_roles WHERE role = r.name)`

// RoleByName returns the role.
func (s *Store) RoleByName(ctx context.Context, name string) (*Role, error) {
	var r Role
	if err := s.pool.QueryRow(ctx, `SELECT r.name, r.description, `+assignedCount+` FROM identity_roles r WHERE r.name = $1`, name).Scan(&r.Name, &r.Description, &r.AssignedCount); err != nil {
		return nil, mapErr(err)
	}
	var err error
	r.Permissions, err = s.strings(ctx, `SELECT permission FROM identity_role_permissions WHERE role = $1 ORDER BY permission`, name)
	return &r, err
}

// ListRoles returns the roles with their permissions; a query keeps the roles whose name or description
// contains it (case insensitive) or that hold a permission containing it. Up to limit+1 roles come back, ordered by
// name and starting after the name `after` ("" for the first page), so the caller can tell whether another page exists.
func (s *Store) ListRoles(ctx context.Context, query, after string, limit int) ([]Role, error) {
	like := ""
	if query != "" {
		like = likeContains(query)
	}
	rows, err := s.pool.Query(ctx, `SELECT r.name, r.description, `+assignedCount+`,
		coalesce((SELECT array_agg(permission ORDER BY permission) FROM identity_role_permissions p WHERE p.role = r.name), '{}')
		FROM identity_roles r
		WHERE ($1 = '' OR r.name ILIKE $1 OR r.description ILIKE $1
		   OR EXISTS (SELECT 1 FROM identity_role_permissions q WHERE q.role = r.name AND q.permission ILIKE $1))
		  AND r.name > $2
		ORDER BY r.name LIMIT $3`, like, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.Name, &r.Description, &r.AssignedCount, &r.Permissions); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountRoles counts the roles ListRoles finds for the query (every page).
func (s *Store) CountRoles(ctx context.Context, query string) (int64, error) {
	like := ""
	if query != "" {
		like = likeContains(query)
	}
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM identity_roles r
		WHERE ($1 = '' OR r.name ILIKE $1 OR r.description ILIKE $1
		   OR EXISTS (SELECT 1 FROM identity_role_permissions q WHERE q.role = r.name AND q.permission ILIKE $1))`, like).Scan(&n)
	return n, err
}

// AssignRole gives a role to a user or a client (exactly one of them is set).
func (s *Store) AssignRole(ctx context.Context, userID, clientID, role string) error {
	return s.roleLink(ctx, `INSERT INTO identity_user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		`INSERT INTO identity_client_roles (client_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`, userID, clientID, role, false)
}

// RevokeRole removes a role from a user or a client.
func (s *Store) RevokeRole(ctx context.Context, userID, clientID, role string) error {
	return s.roleLink(ctx, `DELETE FROM identity_user_roles WHERE user_id = $1 AND role = $2`,
		`DELETE FROM identity_client_roles WHERE client_id = $1 AND role = $2`, userID, clientID, role, true)
}

func (s *Store) roleLink(ctx context.Context, userSQL, clientSQL, userID, clientID, role string, revoke bool) error {
	if (userID == "") == (clientID == "") {
		return errors.New("store: exactly one of user and client is required")
	}
	sql, subject := userSQL, userID
	if clientID != "" {
		sql, subject = clientSQL, clientID
	} else if _, err := uuid.Parse(userID); err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, sql, subject, role)
	if err != nil {
		return mapErr(err)
	}
	if revoke && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- refresh tokens ----

// RefreshToken is a row of identity_refresh_tokens.
type RefreshToken struct {
	ID        string
	FamilyID  string
	UserID    string
	ClientID  string
	SessionID string
	Scope     string
	AuthTime  time.Time
	AMR       []string
	ExpiresAt time.Time
}

// InsertRefreshToken stores a refresh token by the SHA-256 of its value.
func (s *Store) InsertRefreshToken(ctx context.Context, hash []byte, t RefreshToken) error {
	if t.FamilyID == "" {
		t.FamilyID = uuid.NewString()
	}
	var sid any
	if t.SessionID != "" {
		sid = t.SessionID
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO identity_refresh_tokens (family_id, token_hash, user_id, client_id, session_id, scope, auth_time, amr, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.FamilyID, hash, t.UserID, t.ClientID, sid, t.Scope, t.AuthTime, nz(t.AMR), t.ExpiresAt)
	return mapErr(err)
}

// Refresh outcomes.
var (
	ErrRefreshInvalid = errors.New("store: refresh token invalid")
	ErrRefreshReused  = errors.New("store: refresh token reused")
)

// ConsumeRefreshToken marks the token used and returns it. A token that was already used
// revokes the whole family (theft detection) and returns ErrRefreshReused. Unknown, expired,
// revoked tokens, or tokens of another client, return ErrRefreshInvalid.
func (s *Store) ConsumeRefreshToken(ctx context.Context, hash []byte, clientID string) (*RefreshToken, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var t RefreshToken
	var used, revoked *time.Time
	var sid *string
	err = tx.QueryRow(ctx, `SELECT id::text, family_id::text, user_id::text, client_id, session_id, scope, auth_time, amr, expires_at, used_at, revoked_at
		FROM identity_refresh_tokens WHERE token_hash = $1 FOR UPDATE`, hash).
		Scan(&t.ID, &t.FamilyID, &t.UserID, &t.ClientID, &sid, &t.Scope, &t.AuthTime, &t.AMR, &t.ExpiresAt, &used, &revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshInvalid
		}
		return nil, err
	}
	if sid != nil {
		t.SessionID = *sid
	}
	if t.ClientID != clientID || revoked != nil || !t.ExpiresAt.After(time.Now()) {
		return nil, ErrRefreshInvalid
	}
	if used != nil {
		if _, err := tx.Exec(ctx, `UPDATE identity_refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`, t.FamilyID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrRefreshReused
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_refresh_tokens SET used_at = now() WHERE id = $1`, t.ID); err != nil {
		return nil, err
	}
	return &t, tx.Commit(ctx)
}

// RevokeRefreshFamily revokes every token of the family of a token hash.
func (s *Store) RevokeRefreshByHash(ctx context.Context, hash []byte, clientID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE identity_refresh_tokens SET revoked_at = now()
		WHERE revoked_at IS NULL AND client_id = $2 AND family_id = (SELECT family_id FROM identity_refresh_tokens WHERE token_hash = $1)`, hash, clientID)
	return err
}

// RevokeRefreshBySession revokes the refresh tokens that belong to an SSO session.
func (s *Store) RevokeRefreshBySession(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE identity_refresh_tokens SET revoked_at = now() WHERE session_id = $1 AND revoked_at IS NULL`, sessionID)
	return err
}

// RevokeRefreshByUser revokes every refresh token of a user.
func (s *Store) RevokeRefreshByUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE identity_refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

// DeleteExpiredRefreshTokens removes rows that expired more than a day ago.
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM identity_refresh_tokens WHERE expires_at < now() - interval '1 day'`)
	return tag.RowsAffected(), err
}

// ---- exchange policies ----

// ExchangePolicy is a row of identity_exchange_policies.
type ExchangePolicy struct {
	ClientID      string
	Audience      string
	MaxScope      string
	MaxChainDepth int
}

// ExchangePolicyFor returns the policy of (client, audience) or ErrNotFound.
func (s *Store) ExchangePolicyFor(ctx context.Context, clientID, audience string) (*ExchangePolicy, error) {
	var p ExchangePolicy
	err := s.pool.QueryRow(ctx, `SELECT client_id, audience, max_scope, max_chain_depth FROM identity_exchange_policies WHERE client_id = $1 AND audience = $2`,
		clientID, audience).Scan(&p.ClientID, &p.Audience, &p.MaxScope, &p.MaxChainDepth)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

// SetExchangePolicy upserts a policy.
func (s *Store) SetExchangePolicy(ctx context.Context, p ExchangePolicy) error {
	if p.MaxChainDepth == 0 {
		p.MaxChainDepth = 1
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO identity_exchange_policies (client_id, audience, max_scope, max_chain_depth) VALUES ($1,$2,$3,$4)
		ON CONFLICT (client_id, audience) DO UPDATE SET max_scope = EXCLUDED.max_scope, max_chain_depth = EXCLUDED.max_chain_depth`,
		p.ClientID, p.Audience, p.MaxScope, p.MaxChainDepth)
	return mapErr(err)
}

// DeleteExchangePolicy removes a policy.
func (s *Store) DeleteExchangePolicy(ctx context.Context, clientID, audience string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM identity_exchange_policies WHERE client_id = $1 AND audience = $2`, clientID, audience)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PolicyFilter narrows ListExchangePolicies; every empty field matches everything.
type PolicyFilter struct {
	// ClientID is exact.
	ClientID string
	// Query matches the client id, the audience or the max scope (contains, case insensitive).
	Query string
	// Audience matches the audience (contains, case insensitive).
	Audience string
	// AfterClientID and AfterAudience are the key of the last policy of the previous page (both empty for the first).
	AfterClientID string
	AfterAudience string
}

// ListExchangePolicies lists up to limit+1 policies that match the filter, ordered by client and audience, so the
// caller can tell whether another page exists.
func (s *Store) ListExchangePolicies(ctx context.Context, f PolicyFilter, limit int) ([]ExchangePolicy, error) {
	query, audience := "", ""
	if f.Query != "" {
		query = likeContains(f.Query)
	}
	if f.Audience != "" {
		audience = likeContains(f.Audience)
	}
	rows, err := s.pool.Query(ctx, `SELECT client_id, audience, max_scope, max_chain_depth FROM identity_exchange_policies
		WHERE ($1 = '' OR client_id = $1)
		  AND ($2 = '' OR client_id ILIKE $2 OR audience ILIKE $2 OR max_scope ILIKE $2)
		  AND ($3 = '' OR audience ILIKE $3)
		  AND (client_id, audience) > ($4, $5)
		ORDER BY client_id, audience LIMIT $6`, f.ClientID, query, audience, f.AfterClientID, f.AfterAudience, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangePolicy
	for rows.Next() {
		var p ExchangePolicy
		if err := rows.Scan(&p.ClientID, &p.Audience, &p.MaxScope, &p.MaxChainDepth); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- MFA ----

// MFAFactor is a row of identity_user_mfa_factors.
type MFAFactor struct {
	ID           string
	Sealed       []byte
	Confirmed    bool
	LastUsedStep int64
}

// ReplaceMFAFactor stores a new unconfirmed TOTP factor, replacing any previous one.
func (s *Store) ReplaceMFAFactor(ctx context.Context, userID string, sealed []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO identity_user_mfa_factors (user_id, type, secret_sealed) VALUES ($1, 'totp', $2)
		ON CONFLICT (user_id, type) DO UPDATE SET secret_sealed = EXCLUDED.secret_sealed, confirmed_at = NULL, last_used_step = 0, created_at = now()`, userID, sealed)
	return mapErr(err)
}

// MFAFactorOf returns the TOTP factor of the user, or ErrNotFound.
func (s *Store) MFAFactorOf(ctx context.Context, userID string) (*MFAFactor, error) {
	var f MFAFactor
	var confirmed *time.Time
	err := s.pool.QueryRow(ctx, `SELECT id::text, secret_sealed, confirmed_at, last_used_step FROM identity_user_mfa_factors WHERE user_id = $1 AND type = 'totp'`, userID).
		Scan(&f.ID, &f.Sealed, &confirmed, &f.LastUsedStep)
	if err != nil {
		return nil, mapErr(err)
	}
	f.Confirmed = confirmed != nil
	return &f, nil
}

// ConfirmMFAFactor marks the factor confirmed with the step of the first accepted code, turns
// mfa_enabled on and stores the recovery codes, in one transaction.
func (s *Store) ConfirmMFAFactor(ctx context.Context, userID string, step int64, recoveryHashes [][]byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE identity_user_mfa_factors SET confirmed_at = now(), last_used_step = $2 WHERE user_id = $1 AND type = 'totp' AND confirmed_at IS NULL`, userID, step)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_users SET mfa_enabled = true, updated_at = now() WHERE id = $1`, userID); err != nil {
		return err
	}
	if err := replaceRecovery(ctx, tx, userID, recoveryHashes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func replaceRecovery(ctx context.Context, tx pgx.Tx, userID string, hashes [][]byte) error {
	if _, err := tx.Exec(ctx, `DELETE FROM identity_mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO identity_mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return err
		}
	}
	return nil
}

// AdvanceMFAStep records an accepted code step. It succeeds only when the step is newer than
// the last accepted one, so a code cannot be used twice, also by two concurrent requests.
func (s *Store) AdvanceMFAStep(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_user_mfa_factors SET last_used_step = $2
		WHERE user_id = $1 AND type = 'totp' AND confirmed_at IS NOT NULL AND last_used_step < $2`, userID, step)
	return tag.RowsAffected() == 1, err
}

// UpdateMFASealed replaces the sealed secret (re-seal with the current key).
func (s *Store) UpdateMFASealed(ctx context.Context, userID string, sealed []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE identity_user_mfa_factors SET secret_sealed = $2 WHERE user_id = $1 AND type = 'totp'`, userID, sealed)
	return err
}

// UseRecoveryCode consumes a recovery code; false when it does not exist or was used.
func (s *Store) UseRecoveryCode(ctx context.Context, userID string, hash []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_mfa_recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, userID, hash)
	return tag.RowsAffected() == 1, err
}

// RecoveryCodesLeft counts the unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM identity_mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// ResetMFA deletes the factor and the recovery codes and turns mfa_enabled off.
func (s *Store) ResetMFA(ctx context.Context, userID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM identity_user_mfa_factors WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM identity_mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE identity_users SET mfa_enabled = false, updated_at = now() WHERE id = $1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// ---- password resets ----

// CreatePasswordReset stores a reset token by hash and cancels the older ones of the user.
func (s *Store) CreatePasswordReset(ctx context.Context, userID string, hash []byte, ip string, expires time.Time) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE identity_password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`, userID); err != nil {
		return "", err
	}
	var addr any
	if a, err := netip.ParseAddr(ip); err == nil {
		addr = a
	}
	var id string
	if err := tx.QueryRow(ctx, `INSERT INTO identity_password_resets (user_id, token_hash, requested_ip, expires_at) VALUES ($1,$2,$3,$4) RETURNING id::text`,
		userID, hash, addr, expires).Scan(&id); err != nil {
		return "", mapErr(err)
	}
	return id, tx.Commit(ctx)
}

// PeekPasswordReset returns the user of a token that is still usable, without consuming it.
func (s *Store) PeekPasswordReset(ctx context.Context, hash []byte) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx, `SELECT user_id::text FROM identity_password_resets WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`, hash).Scan(&userID)
	if err != nil {
		return "", mapErr(err)
	}
	return userID, nil
}

// ConsumePasswordReset marks the token used and returns its user; ErrNotFound when it does
// not exist, expired or was used (atomic: one winner when requests race).
func (s *Store) ConsumePasswordReset(ctx context.Context, hash []byte) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx, `UPDATE identity_password_resets SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING user_id::text`, hash).Scan(&userID)
	if err != nil {
		return "", mapErr(err)
	}
	return userID, nil
}
