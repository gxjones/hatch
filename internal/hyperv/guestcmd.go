package hyperv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
)

// maxWindowsCommandLine is the CreateProcess limit, excluding the terminating NUL.
const maxWindowsCommandLine = 32766

// GuestLaunch is a program to start inside a running guest.
// Arg is one argv entry. Args, when non-nil, is the full argument vector
// and replaces Arg. wstoudp uses Args because -url and -token are separate flags.
type GuestLaunch struct {
	Exe      string
	Arg      string
	Args     []string
	User     string
	Password string
	Timeout  int
}

// ResolveGuestLaunch checks an hv run / hv up request. A nil launch means the
// caller did not ask to start a program. argSet is true when --arg was present,
// including --arg "".
func ResolveGuestLaunch(exe, arg, argFile, user, password string, argSet bool, timeout int) (*GuestLaunch, error) {
	if strings.TrimSpace(exe) == "" {
		if argSet || argFile != "" {
			return nil, fmt.Errorf("--arg and --arg-file require --exe")
		}
		return nil, nil
	}
	exe = strings.TrimSpace(exe)
	if argSet && argFile != "" {
		return nil, fmt.Errorf("pass only one of --arg or --arg-file")
	}
	if !argSet && argFile == "" {
		return nil, fmt.Errorf("--exe requires --arg or --arg-file")
	}
	if argFile != "" {
		b, err := os.ReadFile(argFile)
		if err != nil {
			return nil, fmt.Errorf("--arg-file: %w", err)
		}
		if !utf8.Valid(b) {
			return nil, fmt.Errorf("--arg-file is not UTF-8: %s", argFile)
		}
		arg = strings.TrimPrefix(string(b), "\uFEFF")
	}
	if strings.TrimSpace(user) == "" {
		return nil, fmt.Errorf("--guest-user is empty")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("--run-timeout must be positive")
	}
	if _, err := windowsCommandLine(exe, arg); err != nil {
		return nil, err
	}
	return &GuestLaunch{
		Exe:      exe,
		Arg:      arg,
		User:     user,
		Password: password,
		Timeout:  timeout,
	}, nil
}

// windowsCommandLine builds the guest CreateProcess command line. The argument
// is a single argv entry, so a multi-kilobyte payload stays one argument.
func windowsCommandLine(exe, arg string) (string, error) {
	if strings.ContainsRune(exe, 0) || strings.ContainsRune(arg, 0) {
		return "", fmt.Errorf("program path and argument cannot contain a NUL")
	}
	if strings.ContainsAny(exe, "\r\n") {
		return "", fmt.Errorf("program path cannot contain a newline")
	}
	if !filepath.IsAbs(exe) {
		return "", fmt.Errorf("guest program path must be absolute")
	}
	line := syscall.EscapeArg(exe) + " " + syscall.EscapeArg(arg)
	if n := len(utf16.Encode([]rune(line))); n > maxWindowsCommandLine {
		return "", fmt.Errorf("command line is %d characters; Windows allows %d", n, maxWindowsCommandLine)
	}
	return line, nil
}

// commandLineFor builds the guest CreateProcess command line.
// A non-nil args vector is passed as separate argv entries.
func commandLineFor(exe, arg string, args []string) (string, error) {
	if args != nil {
		return windowsCommandLineArgs(exe, args)
	}
	return windowsCommandLine(exe, arg)
}

func windowsCommandLineArgs(exe string, args []string) (string, error) {
	if strings.ContainsRune(exe, 0) {
		return "", fmt.Errorf("program path and argument cannot contain a NUL")
	}
	if strings.ContainsAny(exe, "\r\n") {
		return "", fmt.Errorf("program path cannot contain a newline")
	}
	if !filepath.IsAbs(exe) {
		return "", fmt.Errorf("guest program path must be absolute")
	}
	line := syscall.EscapeArg(exe)
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) || strings.ContainsAny(arg, "\r\n") {
			return "", fmt.Errorf("argument cannot contain a NUL or newline")
		}
		line += " " + syscall.EscapeArg(arg)
	}
	if n := len(utf16.Encode([]rune(line))); n > maxWindowsCommandLine {
		return "", fmt.Errorf("command line is %d characters; Windows allows %d", n, maxWindowsCommandLine)
	}
	return line, nil
}

func guestWorkDir(exe string) string {
	dir := filepath.Dir(exe)
	if dir == "." || dir == "" {
		return ""
	}
	return dir
}
