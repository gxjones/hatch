package hyperv

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func TestWindowsCommandLineRoundTrip(t *testing.T) {
	long := strings.Repeat("a\"\\b ", 800) // 4.8 KB before quoting
	plain := strings.Repeat("k", 20000)
	cases := []struct {
		exe string
		arg string
	}{
		{`C:\lab\feed.exe`, ""},
		{`C:\lab\feed.exe`, "simple"},
		{`C:\lab\feed.exe`, "has space"},
		{`C:\lab\feed.exe`, "quote\"inside"},
		{`C:\lab\feed.exe`, `trailing\`},
		{`C:\lab\feed.exe`, `say "hi"`},
		{`C:\lab\feed.exe`, "line1\nline2"},
		{`C:\lab\feed.exe`, "tab\there"},
		{`C:\lab\feed.exe`, "café 🎄"},
		{`C:\lab\feed.exe`, `C:\data\file.txt`},
		{`C:\Program Files\lab\feed.exe`, long},
		{`C:\lab\feed.exe`, plain},
	}
	for _, tc := range cases {
		line, err := windowsCommandLine(tc.exe, tc.arg)
		if err != nil {
			t.Fatalf("exe %q arg len %d: %v", tc.exe, len(tc.arg), err)
		}
		got, err := commandLineArgs(line)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.exe, err)
		}
		if len(got) != 2 || got[0] != tc.exe || got[1] != tc.arg {
			t.Fatalf("exe %q arg len %d parsed %#v", tc.exe, len(tc.arg), got)
		}
	}
}

func TestWindowsCommandLineRejects(t *testing.T) {
	if _, err := windowsCommandLine(`feed.exe`, "x"); err == nil {
		t.Fatal("relative path was accepted")
	}
	if _, err := windowsCommandLine(`C:\lab\feed.exe`, "a\x00b"); err == nil {
		t.Fatal("NUL argument was accepted")
	}
	if _, err := windowsCommandLine(`C:\lab\feed.exe`, strings.Repeat("a", 40000)); err == nil {
		t.Fatal("over-long command line was accepted")
	}
}

func TestWstoudpCommandLine(t *testing.T) {
	launch, err := ResolveWstoudpLaunch("wss://vm.example/wireguard", "tok en", "127.0.0.1:51820", "User", "pw", 30)
	if err != nil {
		t.Fatal(err)
	}
	if launch.Exe != WstoudpExe {
		t.Fatalf("exe %s", launch.Exe)
	}
	line, err := commandLineFor(launch.Exe, launch.Arg, launch.Args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := commandLineArgs(line)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{WstoudpExe, "-url", "wss://vm.example/wireguard", "-token", "tok en", "-listen", "127.0.0.1:51820"}
	if len(got) != len(want) {
		t.Fatalf("parsed %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %#v", got)
		}
	}

	if _, err := ResolveWstoudpLaunch("http://vm.example/", "tok", "", "User", "pw", 30); err == nil {
		t.Fatal("http URL was accepted")
	}
	if _, err := ResolveWstoudpLaunch("wss://vm.example/", "", "", "User", "pw", 30); err == nil {
		t.Fatal("empty token was accepted")
	}
	if _, err := ResolveWstoudpLaunch("wss://vm.example/", "a\nb", "", "User", "pw", 30); err == nil {
		t.Fatal("newline token was accepted")
	}
	if _, err := ResolveWstoudpLaunch("wss://vm.example/", "tok", "51820", "User", "pw", 30); err == nil {
		t.Fatal("listen without a host was accepted")
	}
}

func TestResolveGuestLaunchArgFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.txt")
	body := "\uFEFF" + strings.Repeat("cfg \"v\"\n", 500)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveGuestLaunch(`C:\lab\feed.exe`, "", path, "User", "pw", false, 30)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimPrefix(body, "\uFEFF")
	if got.Arg != want {
		t.Fatalf("arg len %d, want %d", len(got.Arg), len(want))
	}
	if _, err := windowsCommandLine(got.Exe, got.Arg); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveGuestLaunch(`C:\lab\feed.exe`, "x", path, "User", "pw", true, 30); err == nil {
		t.Fatal("both --arg and --arg-file were accepted")
	}
	if _, err := ResolveGuestLaunch("", "x", "", "User", "pw", true, 30); err == nil {
		t.Fatal("--arg without --exe was accepted")
	}
	bad := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(bad, []byte{0xff, 0xfe, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGuestLaunch(`C:\lab\feed.exe`, "", bad, "User", "pw", false, 30); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
	if got, err := ResolveGuestLaunch("", "", "", "User", "pw", false, 30); err != nil || got != nil {
		t.Fatalf("empty request = (%v, %v), want nil, nil", got, err)
	}
}

func commandLineArgs(cmd string) ([]string, error) {
	ptr, err := syscall.UTF16PtrFromString(cmd)
	if err != nil {
		return nil, err
	}
	var argc int32
	raw, _, callErr := commandLineToArgvW.Call(uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(&argc)))
	if raw == 0 {
		if callErr != syscall.Errno(0) {
			return nil, callErr
		}
		return nil, syscall.EINVAL
	}
	defer syscall.LocalFree(syscall.Handle(raw))
	ptrs := unsafe.Slice((**uint16)(unsafe.Pointer(raw)), int(argc))
	out := make([]string, argc)
	for i, p := range ptrs {
		out[i] = utf16PtrToString(p)
	}
	return out, nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for *(*uint16)(unsafe.Add(unsafe.Pointer(p), n*2)) != 0 {
		n++
	}
	return string(utf16.Decode(unsafe.Slice(p, n)))
}

var commandLineToArgvW = syscall.NewLazyDLL("shell32.dll").NewProc("CommandLineToArgvW")
