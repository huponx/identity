package store

import (
	"context"
	"strings"
)

// likePrefix turns text into a LIKE pattern that matches values starting with it (the LIKE
// metacharacters of the text are escaped with a backslash).
func likePrefix(text string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(text) + "%"
}

// ListUsers returns up to limit users ordered by email, starting after the email `after`
// ("" for the first page), whose email starts with prefix (case insensitive). It returns
// limit+1 rows at most so the caller can tell whether another page exists, together with the
// roles of each user.
func (s *Store) ListUsers(ctx context.Context, prefix, after string, limit int) ([]User, map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM identity_users
		WHERE email LIKE $1 ESCAPE '\' AND email > $2 ORDER BY email LIMIT $3`,
		likePrefix(NormalizeEmail(prefix)), after, limit+1)
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
