package account

import "testing"

func TestMailPasswordChanged(t *testing.T) {
	if mailPasswordChanged(false) {
		t.Error("first password must not send the changed mail")
	}
	if !mailPasswordChanged(true) {
		t.Error("replaced password must send the changed mail")
	}
}
