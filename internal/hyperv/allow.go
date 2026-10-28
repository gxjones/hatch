package hyperv

import (
	"fmt"
	"net"
	"strings"
)

// ValidateAllowHost accepts an IPv4 address or a DNS name. The guest may open
// TCP 443 only to the addresses that name resolves to.
func ValidateAllowHost(host string) error {
	if host == "" || strings.TrimSpace(host) != host {
		return fmt.Errorf("--allow-host must be an IPv4 address or a DNS name")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, " \t/\\?#@,") {
		return fmt.Errorf("--allow-host must be an IPv4 address or a DNS name, not a URL")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("--allow-host must be an IPv4 address or a DNS name")
		}
		return nil
	}
	if strings.Contains(host, ":") || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return fmt.Errorf("--allow-host must be an IPv4 address or a DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("--allow-host must be an IPv4 address or a DNS name")
		}
		for _, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return fmt.Errorf("--allow-host must be an IPv4 address or a DNS name")
		}
	}
	return nil
}
