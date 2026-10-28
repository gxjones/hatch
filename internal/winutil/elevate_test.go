package winutil

import "testing"

func TestTokenHasSID(t *testing.T) {
	if !tokenHasSID("S-1-5-32-545") {
		t.Fatal("current token should include BUILTIN\\Users")
	}
	if tokenHasSID("not-a-sid") {
		t.Fatal("a malformed SID should not report membership")
	}
}
