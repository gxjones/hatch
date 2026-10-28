package hyperv

import (
	"encoding/json"
	"testing"
)

func TestValidateAllowHost(t *testing.T) {
	ok := []string{"example.com", "a.b", "downloads.example.co.uk", "1.2.3.4", "X"}
	bad := []string{"", " example.com", "example.com ", "https://example.com", "example.com/path", "example.com:443", "2001:db8::1", "exa mple.com", ".", "-bad.com", "bad-.com"}
	for _, host := range ok {
		if err := ValidateAllowHost(host); err != nil {
			t.Errorf("want ok %q: %v", host, err)
		}
	}
	for _, host := range bad {
		if err := ValidateAllowHost(host); err == nil {
			t.Errorf("want reject %q", host)
		}
	}
}

func TestStringListUnmarshal(t *testing.T) {
	var one stringList
	if err := json.Unmarshal([]byte(`"1.2.3.4"`), &one); err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0] != "1.2.3.4" {
		t.Fatalf("one: %#v", one)
	}
	var many stringList
	if err := json.Unmarshal([]byte(`["8.8.8.8","1.1.1.1"]`), &many); err != nil {
		t.Fatal(err)
	}
	if len(many) != 2 || many[1] != "1.1.1.1" {
		t.Fatalf("many: %#v", many)
	}
}
