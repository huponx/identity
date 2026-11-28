// Package catalog derives the wildcard permissions from the declared ones. Wildcards are not defined in a proto
// and not stored: adding a service or a permission in code adds the wildcards that cover it.
package catalog

import (
	"sort"
	"strings"

	"github.com/huponx/gocommon/authz"
)

// Wildcards returns the wildcards that cover at least one of the permission names, sorted:
//
//   - everything (always present, also for an empty catalog)
//     <service>:*                a whole service
//     <service>:*:<action>       one action on every resource (names of three segments)
//     <service>:<resource>:*     every action on one resource (names of three or more segments)
func Wildcards(names []string) []string {
	set := map[string]bool{"*": true}
	for _, n := range names {
		segs := strings.Split(n, ":")
		if len(segs) < 2 || strings.Contains(n, "*") {
			continue
		}
		set[segs[0]+":*"] = true
		if len(segs) == 3 {
			set[segs[0]+":*:"+segs[2]] = true
		}
		if len(segs) >= 3 {
			set[segs[0]+":"+segs[1]+":*"] = true
		}
	}
	out := make([]string, 0, len(set))
	for w := range set {
		if authz.Valid(w) {
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}

// Known answers "may a role be given this name": it is a declared (not retired) permission or a generated wildcard.
type Known struct {
	active    map[string]bool
	wildcards map[string]bool
}

// NewKnown builds the set from the names of the permissions that are not retired.
func NewKnown(active []string) *Known {
	k := &Known{active: map[string]bool{}, wildcards: map[string]bool{}}
	for _, n := range active {
		k.active[n] = true
	}
	for _, w := range Wildcards(active) {
		k.wildcards[w] = true
	}
	return k
}

// Has reports whether the name is a declared permission or a generated wildcard.
func (k *Known) Has(name string) bool { return k.active[name] || k.wildcards[name] }

// Wildcard reports whether the name is a generated wildcard.
func (k *Known) Wildcard(name string) bool { return k.wildcards[name] }

// Wildcards lists the generated wildcards, sorted.
func (k *Known) Wildcards() []string {
	out := make([]string, 0, len(k.wildcards))
	for w := range k.wildcards {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// Stale returns the names of a role grant that do nothing any more: a retired or deleted permission, a wildcard
// that covers no declared permission. They are kept until an administrator removes them.
func (k *Known) Stale(granted []string) []string {
	var out []string
	for _, g := range granted {
		if !k.Has(g) {
			out = append(out, g)
		}
	}
	return out
}
