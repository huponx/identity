package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Permission is an entry of the catalog.
type Permission struct {
	Name        string
	Description string
	RoleCount   int64
}

// ListPermissions returns the catalog ordered by name, with the number of roles that hold each; a query keeps
// the entries whose name or description contains it (case insensitive). Up to limit+1 entries come back, starting
// after the name `after` ("" for the first page), so the caller can tell whether another page exists.
func (s *Store) ListPermissions(ctx context.Context, query, after string, limit int) ([]Permission, error) {
	like := ""
	if query != "" {
		like = likeContains(query)
	}
	rows, err := s.pool.Query(ctx, `SELECT p.permission, p.description,
		(SELECT count(*) FROM identity_role_permissions rp WHERE rp.permission = p.permission)
		FROM identity_permissions p
		WHERE ($1 = '' OR p.permission ILIKE $1 OR p.description ILIKE $1) AND p.permission > $2
		ORDER BY p.permission LIMIT $3`, like, after, limit+1)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.Name, &p.Description, &p.RoleCount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, mapErr(rows.Err())
}

// CountPermissions counts the entries ListPermissions finds for the query (every page).
func (s *Store) CountPermissions(ctx context.Context, query string) (int64, error) {
	like := ""
	if query != "" {
		like = likeContains(query)
	}
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM identity_permissions p
		WHERE ($1 = '' OR p.permission ILIKE $1 OR p.description ILIKE $1)`, like).Scan(&n)
	return n, mapErr(err)
}

// CreatePermission adds an entry; ErrConflict when it exists.
func (s *Store) CreatePermission(ctx context.Context, name, description string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO identity_permissions (permission, description) VALUES ($1, $2)`, name, description)
	return mapErr(err)
}

// UpdatePermission changes the description; ErrNotFound when there is no such entry.
func (s *Store) UpdatePermission(ctx context.Context, name, description string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_permissions SET description = $2 WHERE permission = $1`, name, description)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePermission removes an entry; ErrPermissionInUse while a role holds it, ErrNotFound when missing.
func (s *Store) DeletePermission(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM identity_permissions WHERE permission = $1`, name)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23503" {
		return ErrPermissionInUse
	}
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PermissionRoles lists the roles that hold the permission (for the message of a refused delete).
func (s *Store) PermissionRoles(ctx context.Context, name string) ([]string, error) {
	return s.strings(ctx, `SELECT role FROM identity_role_permissions WHERE permission = $1 ORDER BY role`, name)
}
