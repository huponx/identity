package store

import (
	"context"
	"strconv"
	"strings"
)

// likePrefix turns text into a LIKE pattern that matches values starting with it (the LIKE
// metacharacters of the text are escaped with a backslash).
func likePrefix(text string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(text) + "%"
}

// UserFilter narrows ListUsers; every empty field matches everyone.
type UserFilter struct {
	EmailPrefix  string // case insensitive
	NameContains string // case insensitive
	Status       string // "awaiting_approval", "pending", "active" or "disabled" (the rule of the API: disabled first, then no password = pending)
	Role         string
}

func likeContains(text string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(text) + "%"
}

// ListUsers returns up to limit users ordered by email, starting after the email `after`
// ("" for the first page), that match the filter. It returns limit+1 rows at most so the caller
// can tell whether another page exists, together with the roles of each user.
func (s *Store) ListUsers(ctx context.Context, f UserFilter, after string, limit int) ([]User, map[string][]string, error) {
	where := []string{`deleted_at IS NULL`, `email LIKE $1 ESCAPE '\'`, `email > $2`}
	args := []any{likePrefix(NormalizeEmail(f.EmailPrefix)), after}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.Replace(cond, "?", "$"+strconv.Itoa(len(args)), 1))
	}
	if n := strings.TrimSpace(f.NameContains); n != "" {
		add(`lower(name) LIKE ? ESCAPE '\'`, likeContains(strings.ToLower(n)))
	}
	switch f.Status {
	case "disabled":
		where = append(where, `disabled`)
	case "awaiting_approval":
		where = append(where, `NOT disabled AND pending_approval`)
	case "pending":
		where = append(where, `NOT disabled AND password_hash IS NULL AND NOT pending_approval`)
	case "active":
		where = append(where, `NOT disabled AND password_hash IS NOT NULL`)
	}
	if f.Role != "" {
		add(`EXISTS (SELECT 1 FROM identity_user_roles r WHERE r.user_id = identity_users.id AND r.role = ?)`, f.Role)
	}
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM identity_users WHERE `+strings.Join(where, " AND ")+
		` ORDER BY email LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rows.Close()
	var users []User
	var ids []string
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, nil, err
		}
		users = append(users, *u)
		ids = append(ids, u.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, mapErr(err)
	}
	roles := map[string][]string{}
	if len(ids) == 0 {
		return users, roles, nil
	}
	rr, err := s.pool.Query(ctx, `SELECT user_id::text, role FROM identity_user_roles WHERE user_id::text = ANY($1) ORDER BY role`, ids)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	defer rr.Close()
	for rr.Next() {
		var id, role string
		if err := rr.Scan(&id, &role); err != nil {
			return nil, nil, err
		}
		roles[id] = append(roles[id], role)
	}
	return users, roles, mapErr(rr.Err())
}
