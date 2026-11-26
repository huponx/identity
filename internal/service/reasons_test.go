package service

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	errorCall  = regexp.MustCompile(`apperror\.(InvalidArgument|NotFound|Unauthenticated|PermissionDenied|AlreadyExists|FailedPrecondition|Unavailable|Wrap)\(`)
	reasonCall = regexp.MustCompile(`\.WithReason\("([^"]*)"`)
	snakeCase  = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
)

// withoutReason are the errors a user cannot act on, or whose text is already the message of another layer: the client shows
// the generic sentence of their code (errors.code.*).
var withoutReason = []string{
	`"not found"`,
	`"already exists"`,
	`InvalidArgument(err.Error())`,
	`InvalidArgument(te.Desc)`,
	`"internal error"`,
}

// Every error the service returns carries a stable reason, which the web apps translate (errors.reason.*), unless it is
// listed in withoutReason.
func TestEveryErrorHasAReason(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			if !errorCall.MatchString(line) {
				continue
			}
			stmt := line
			if i+1 < len(lines) && !strings.HasSuffix(strings.TrimSpace(line), ")") { // a call over two lines
				stmt += lines[i+1]
			}
			m := reasonCall.FindStringSubmatch(stmt)
			if m == nil {
				if !allowed(line) {
					t.Errorf("%s:%d has no reason: %s", f, i+1, strings.TrimSpace(line))
				}
				continue
			}
			if !snakeCase.MatchString(m[1]) {
				t.Errorf("%s:%d reason %q is not snake_case", f, i+1, m[1])
			}
		}
	}
}

func allowed(line string) bool {
	for _, a := range withoutReason {
		if strings.Contains(line, a) {
			return true
		}
	}
	return false
}
