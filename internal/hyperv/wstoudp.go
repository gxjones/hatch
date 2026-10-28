package hyperv

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// WstoudpExe is the console proxy baked into the gold guest image.
// It listens on 127.0.0.1:51820 unless --ws-listen overrides that.
const WstoudpExe = `C:\Program Files\wstoudp\wstoudp.exe`

// ResolveWstoudpLaunch checks an hv up / hv run request that starts wstoudp.
// The WebSocket URL and token are arguments, not part of the image.
func ResolveWstoudpLaunch(rawURL, token, listen, user, password string, timeout int) (*GuestLaunch, error) {
	rawURL = strings.TrimSpace(rawURL)
	token = strings.TrimSpace(token)
	listen = strings.TrimSpace(listen)
	if rawURL == "" || token == "" {
		return nil, fmt.Errorf("wstoudp needs --ws-url and --ws-token")
	}
	if err := validateWSURL(rawURL); err != nil {
		return nil, err
	}
	if strings.ContainsAny(token, "\r\n\x00") {
		return nil, fmt.Errorf("--ws-token cannot contain a newline or NUL")
	}
	if listen != "" {
		if _, _, err := net.SplitHostPort(listen); err != nil {
			return nil, fmt.Errorf("--ws-listen must be host:port")
		}
	}
	if strings.TrimSpace(user) == "" {
		return nil, fmt.Errorf("--guest-user is empty")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("--run-timeout must be positive")
	}
	args := []string{"-url", rawURL, "-token", token}
	if listen != "" {
		args = append(args, "-listen", listen)
	}
	launch := &GuestLaunch{
		Exe:      WstoudpExe,
		Args:     args,
		User:     user,
		Password: password,
		Timeout:  timeout,
	}
	if _, err := commandLineFor(launch.Exe, launch.Arg, launch.Args); err != nil {
		return nil, err
	}
	return launch, nil
}

func validateWSURL(raw string) error {
	if strings.ContainsAny(raw, "\r\n\x00 \t") {
		return fmt.Errorf("--ws-url cannot contain whitespace or a NUL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "ws" && u.Scheme != "wss") || u.User != nil {
		return fmt.Errorf("--ws-url must be a ws:// or wss:// URL")
	}
	return nil
}
