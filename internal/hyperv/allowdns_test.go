package hyperv

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNameAllowed(t *testing.T) {
	if !nameAllowed("www.google.com", "google.com") || !nameAllowed("accounts.google.com.", "google.com") || !nameAllowed("google.com", "www.google.com") {
		t.Fatal("expected google names to match")
	}
	if nameAllowed("gstatic.com", "google.com") || nameAllowed("notgoogle.com", "google.com") || nameAllowed("google.com.evil.com", "google.com") {
		t.Fatal("expected unrelated names to be rejected")
	}
	if nameAllowed("www.google.com", "142.251.32.14") {
		t.Fatal("an address allow-host does not match names")
	}
}

func TestDNSARoundTrip(t *testing.T) {
	q := dnsQuery("www.google.com", 1)
	name, qtype, err := firstQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	if name != "www.google.com" || qtype != 1 {
		t.Fatalf("question %s type %d", name, qtype)
	}
	resp := dnsA(q, []net.IP{net.ParseIP("142.251.150.119")})
	if resp[2]&0x80 == 0 {
		t.Fatal("response bit not set")
	}
	if !bytesContains(resp, []byte{142, 251, 150, 119}) {
		t.Fatalf("missing address in %x", resp)
	}
	empty := dnsHeader(q, 0, 0)
	if len(empty) != len(q) {
		t.Fatalf("empty response len %d want %d", len(empty), len(q))
	}
}

func TestReadAllowGuests(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`{"hosts":{"sbx-old":"172.29.248.10","sbx-new":{"ip":"172.29.248.11","allowHost":"google.com"}}}`)
	if err := os.WriteFile(filepath.Join(dir, "allow-net.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readAllowGuests(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got["sbx-old"].IP != "172.29.248.10" || got["sbx-old"].AllowHost != "" {
		t.Fatalf("old entry: %+v", got["sbx-old"])
	}
	if got["sbx-new"].IP != "172.29.248.11" || got["sbx-new"].AllowHost != "google.com" {
		t.Fatalf("new entry: %+v", got["sbx-new"])
	}
	raw, _ := json.Marshal(got)
	if len(raw) == 0 {
		t.Fatal("empty")
	}
}

func dnsQuery(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range splitDot(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return q
}

func splitDot(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return out
}

func bytesContains(b, sub []byte) bool {
	if len(sub) == 0 || len(sub) > len(b) {
		return false
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
