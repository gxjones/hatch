package wsb

import (
	"strings"
	"testing"
)

func TestBuildDefaultsAndEscape(t *testing.T) {
	b, err := Build(Options{
		MemoryMB:     2048,
		Networking:   false,
		GPU:          true,
		Clipboard:    true,
		HostFolder:   `C:\work & files`,
		GuestFolder:  `C:\guest`,
		MapReadOnly:  true,
		LogonCommand: `cmd.exe /c echo hi`,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"<Networking>Disable</Networking>",
		"<VGpu>Enable</VGpu>",
		"<MemoryInMB>2048</MemoryInMB>",
		"<ClipboardRedirection>Enable</ClipboardRedirection>",
		"C:\\work &amp; files",
		"<ReadOnly>true</ReadOnly>",
		"<Command>cmd.exe /c echo hi</Command>",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
}

func TestBuildOmitsEmptyMap(t *testing.T) {
	b, err := Build(Options{MemoryMB: 1024, GPU: true, Networking: true, Clipboard: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "MappedFolder") {
		t.Fatalf("unexpected mapped folder:\n%s", b)
	}
}
