package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/huponx/gocommon/authz"
	"github.com/jackc/pgx/v5"
)

// Permission is an entry of the catalog. The catalog is written by SyncPermissions only.
type Permission struct {
	Name        string
	Description string
	Service     string
	Retired     bool
	RoleCount   int64
}

// ErrInvalidPermissionDef: a name given to SyncPermissions is malformed or outside the namespace of the service.
var ErrInvalidPermissionDef = errors.New("store: invalid permission definition")

// PermissionDef is a permission a service declares.
type PermissionDef struct {
	Name        string
	Description string
	RenamedFrom string
}

// SyncResult counts what one SyncPermissions changed. Log has one line per change.
type SyncResult struct {
	Inserted, Updated, Retired, Deleted, Renamed int
	Log                                          []string
}

// ListCatalog returns every entry of the catalog (retired ones too) ordered by name, with the number of roles that
// hold each. The catalog is small (the permissions of the services), so callers filter and page in memory.
func (s *Store) ListCatalog(ctx context.Context) ([]Permission, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.permission, p.description, p.service, p.retired_at IS NOT NULL,
		(SELECT count(*) FROM identity_role_permissions rp WHERE rp.permission = p.permission)
		FROM identity_permissions p ORDER BY p.permission`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.Name, &p.Description, &p.Service, &p.Retired, &p.RoleCount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, mapErr(rows.Err())
}

// ActivePermissions lists the names of the permissions that are not retired.
func (s *Store) ActivePermissions(ctx context.Context) ([]string, error) {
	return s.strings(ctx, `SELECT permission FROM identity_permissions WHERE retired_at IS NULL ORDER BY permission`)
}

// RoleCountOf counts the roles that hold each of the names (wildcards included).
func (s *Store) RoleCountOf(ctx context.Context, names []string) (map[string]int64, error) {
	out := map[string]int64{}
	rows, err := s.pool.Query(ctx, `SELECT permission, count(*) FROM identity_role_permissions WHERE permission = ANY($1) GROUP BY permission`, names)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var c int64
		if err := rows.Scan(&n, &c); err != nil {
			return nil, err
		}
		out[n] = c
	}
	return out, mapErr(rows.Err())
}

// syncLockKey serializes the syncs of all services (two pods of a rolling deploy start together).
const syncLockKey = 7261001

// SyncPermissions makes the catalog rows of one service equal to defs, in one transaction (all changes or none):
//
//   - a name that is new is inserted; a changed description is updated; a retired one that is declared again is restored;
//   - renamed_from: when the old name is a row of the service that is no longer declared, its role grants move to
//     the new name and the old row goes;
//   - a row of the service that is not declared any more is deleted when no role holds it, else retired (the grants
//     stay, so a re-add or a rename restores them); a retired row that no role holds any more is deleted.
//
// It never touches rows of another service, identity_user_roles, or grants of wildcards. Every name must be a
// concrete valid permission that starts with "<service>:".
func (s *Store) SyncPermissions(ctx context.Context, service string, defs []PermissionDef) (*SyncResult, error) {
	if service == "" || strings.ContainsAny(service, ":*") {
		return nil, fmt.Errorf("%w: invalid service %q", ErrInvalidPermissionDef, service)
	}
	declared := map[string]PermissionDef{}
	for _, d := range defs {
		if err := checkOwnName(service, d.Name); err != nil {
			return nil, err
		}
		if d.RenamedFrom != "" {
			if err := checkOwnName(service, d.RenamedFrom); err != nil {
				return nil, err
			}
		}
		if _, dup := declared[d.Name]; dup {
			return nil, fmt.Errorf("%w: %q is declared twice", ErrInvalidPermissionDef, d.Name)
		}
		declared[d.Name] = d
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, syncLockKey); err != nil {
		return nil, err
	}

	type row struct {
		description string
		retired     bool
	}
	rows, err := tx.Query(ctx, `SELECT permission, description, retired_at IS NOT NULL FROM identity_permissions WHERE service = $1`, service)
	if err != nil {
		return nil, err
	}
	existing := map[string]row{}
	for rows.Next() {
		var name string
		var r row
		if err := rows.Scan(&name, &r.description, &r.retired); err != nil {
			rows.Close()
			return nil, err
		}
		existing[name] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	res := &SyncResult{}
	logf := func(format string, a ...any) { res.Log = append(res.Log, fmt.Sprintf(format, a...)) }

	// renames first, so the grants are on the new name before the old row is looked at
	for _, name := range sortedKeys(declared) {
		d := declared[name]
		old := d.RenamedFrom
		if old == "" || old == name {
			continue
		}
		if _, ok := existing[old]; !ok {
			continue
		}
		if _, stillDeclared := declared[old]; stillDeclared {
			continue
		}
		if _, ok := existing[name]; !ok {
			if _, err := tx.Exec(ctx, `INSERT INTO identity_permissions (permission, description, service) VALUES ($1, $2, $3)`, name, d.Description, service); err != nil {
				return nil, err
			}
			existing[name] = row{description: d.Description}
			res.Inserted++
			logf("insert %s", name)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_role_permissions (role, permission)
			SELECT role, $2 FROM identity_role_permissions WHERE permission = $1 ON CONFLICT DO NOTHING`, old, name); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity_role_permissions WHERE permission = $1`, old); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity_permissions WHERE permission = $1`, old); err != nil {
			return nil, err
		}
		delete(existing, old)
		res.Renamed++
		logf("rename %s -> %s (role grants moved)", old, name)
	}

	for _, name := range sortedKeys(declared) {
		d := declared[name]
		r, ok := existing[name]
		switch {
		case !ok:
			if _, err := tx.Exec(ctx, `INSERT INTO identity_permissions (permission, description, service) VALUES ($1, $2, $3)`, name, d.Description, service); err != nil {
				return nil, mapErr(err)
			}
			res.Inserted++
			logf("insert %s", name)
		case r.description != d.Description || r.retired:
			if _, err := tx.Exec(ctx, `UPDATE identity_permissions SET description = $2, retired_at = NULL WHERE permission = $1`, name, d.Description); err != nil {
				return nil, err
			}
			res.Updated++
			if r.retired {
				logf("restore %s", name)
			} else {
				logf("update %s", name)
			}
		}
	}

	for _, name := range sortedKeys(existing) {
		if _, ok := declared[name]; ok {
			continue
		}
		if err := retireOrDelete(ctx, tx, name, existing[name].retired, res); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// RetireUnclaimed applies the removal rule to the rows no service owns (service ”): rows an administrator created
// before the catalog became read only. Called once identity has synced the services it owns.
func (s *Store) RetireUnclaimed(ctx context.Context) (*SyncResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, syncLockKey); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT permission, retired_at IS NOT NULL FROM identity_permissions WHERE service = ''`)
	if err != nil {
		return nil, err
	}
	type row struct {
		name    string
		retired bool
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.retired); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res := &SyncResult{}
	for _, r := range list {
		if err := retireOrDelete(ctx, tx, r.name, r.retired, res); err != nil {
			return nil, err
		}
	}
	return res, tx.Commit(ctx)
}

func retireOrDelete(ctx context.Context, tx pgx.Tx, name string, alreadyRetired bool, res *SyncResult) error {
	var held bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM identity_role_permissions WHERE permission = $1)`, name).Scan(&held); err != nil {
		return err
	}
	switch {
	case !held:
		if _, err := tx.Exec(ctx, `DELETE FROM identity_permissions WHERE permission = $1`, name); err != nil {
			return err
		}
		res.Deleted++
		res.Log = append(res.Log, "delete "+name)
	case !alreadyRetired:
		if _, err := tx.Exec(ctx, `UPDATE identity_permissions SET retired_at = now() WHERE permission = $1`, name); err != nil {
			return err
		}
		res.Retired++
		res.Log = append(res.Log, "retire "+name+" (a role still holds it, grants kept)")
	}
	return nil
}

func checkOwnName(service, name string) error {
	if !authz.Valid(name) || strings.Contains(name, "*") || strings.Count(name, ":") < 2 {
		return fmt.Errorf("%w: %q is not a permission name (service:resource:action)", ErrInvalidPermissionDef, name)
	}
	if !strings.HasPrefix(name, service+":") {
		return fmt.Errorf("%w: %q is outside the namespace %q", ErrInvalidPermissionDef, name, service+":")
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermissionRoles lists the roles that hold the permission.
func (s *Store) PermissionRoles(ctx context.Context, name string) ([]string, error) {
	return s.strings(ctx, `SELECT role FROM identity_role_permissions WHERE permission = $1 ORDER BY role`, name)
}
