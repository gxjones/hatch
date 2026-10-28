package hyperv

import "testing"

func TestValidateName(t *testing.T) {
	ok := []string{"sbx-1", "Gold", "a", "parent.v2", "A_b-c.1"}
	bad := []string{"", " has space", "../x", `C:\vm`, "quote\"", "-lead", "semi;colon"}
	for _, n := range ok {
		if err := ValidateName(n); err != nil {
			t.Errorf("want ok %q: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := ValidateName(n); err == nil {
			t.Errorf("want reject %q", n)
		}
	}
}
