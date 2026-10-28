package hyperv

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"hatch/internal/config"
)

const allowGateway = "172.29.248.1"

// RunAllowDNS answers the guest network and opens TCP 443 to addresses
// returned for the clone's allow-host and its subdomains.
func RunAllowDNS(root string) (err error) {
	if err = os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	// The proxy log and pid live in the user profile. Copies under the data
	// root were created by an elevated process, so this token can only read
	// them and the proxy exits before it listens.
	state := config.Dir()
	if err = os.MkdirAll(state, 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(state, "allow-dns.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	defer func() {
		if err != nil {
			log.Printf("exit: %v", err)
		}
	}()
	pidPath := filepath.Join(state, "allow-dns.pid")
	if err = os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		return err
	}
	defer os.Remove(pidPath)

	ip := net.ParseIP(allowGateway)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 53})
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: 53})
	if err != nil {
		return err
	}
	defer tcp.Close()
	log.Printf("listening on %s:53", allowGateway)
	go serveAllowTCP(tcp, root)
	serveAllowUDP(udp, root)
	return nil
}

// EnsureAllowDNS starts the DNS proxy when nothing is listening on the
// allow-network gateway. Running allow-mode clones lose name lookups, and so
// new TCP 443 addresses, while the proxy is down.
func EnsureAllowDNS() error {
	if listening, err := allowDNSListening(); err != nil || listening {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := command(exe, "allow-dns")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start allow DNS proxy: %w", err)
	}
	_ = cmd.Process.Release()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if listening, err := allowDNSListening(); err != nil || listening {
			return err
		}
	}
	return errors.New("allow DNS proxy did not listen on port 53")
}

// allowDNSListening reports whether another process holds the proxy's UDP port.
func allowDNSListening() (bool, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(allowGateway), Port: 53})
	if err == nil {
		conn.Close()
		return false, nil
	}
	if errors.Is(err, syscall.Errno(10048)) { // WSAEADDRINUSE
		return true, nil
	}
	return false, fmt.Errorf("check allow DNS proxy: %w", err)
}

func AddAllowIPs(vm string, ips []string) error {
	if vm == "" || len(ips) == 0 {
		return nil
	}
	var dest struct {
		Added stringList `json:"added"`
	}
	return call("allow-acl", map[string]string{
		"SBX_NAME":      vm,
		"SBX_ALLOW_IPS": strings.Join(ips, ","),
	}, &dest)
}

func serveAllowUDP(pc *net.UDPConn, root string) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("udp read: %v", err)
			continue
		}
		resp := answerDNS(append([]byte(nil), buf[:n]...), ipKey(addr.IP), root)
		if len(resp) == 0 {
			continue
		}
		if _, err := pc.WriteToUDP(resp, addr); err != nil {
			log.Printf("udp write: %v", err)
		}
	}
}

func serveAllowTCP(ln *net.TCPListener, root string) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("tcp accept: %v", err)
			continue
		}
		go func(c *net.TCPConn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var n uint16
			if err := binary.Read(c, binary.BigEndian, &n); err != nil || n == 0 || n > 4096 {
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			resp := answerDNS(buf, ipKey(c.RemoteAddr().(*net.TCPAddr).IP), root)
			if len(resp) == 0 {
				return
			}
			if err := binary.Write(c, binary.BigEndian, uint16(len(resp))); err != nil {
				return
			}
			_, _ = c.Write(resp)
		}(conn)
	}
}

func answerDNS(query []byte, guestIP, root string) []byte {
	name, qtype, err := firstQuestion(query)
	if err != nil {
		return nil
	}
	switch qtype {
	case 28, 65: // AAAA, HTTPS/SVCB. No IPv6 path, and HTTPS records can carry addresses.
		return dnsHeader(query, 0, 0)
	case 1: // A
		ips, err := lookupA(name)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return dnsHeader(query, 0, 3)
			}
			log.Printf("lookup %s: %v", name, err)
			return dnsHeader(query, 0, 2)
		}
		if vm, host, ok := guestAllow(root, guestIP); ok && nameAllowed(name, host) {
			var add []string
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					add = append(add, v4.String())
				}
			}
			if err := ensureAllow(vm, add); err != nil {
				log.Printf("allow %s %s: %v", vm, name, err)
				return dnsHeader(query, 0, 2)
			}
			log.Printf("allow %s %s -> %s", vm, name, strings.Join(add, ","))
		}
		return dnsA(query, ips)
	default:
		return dnsHeader(query, 0, 0)
	}
}

func nameAllowed(qname, allowHost string) bool {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(allowHost)), ".")
	if q == "" || h == "" || net.ParseIP(h) != nil {
		return false
	}
	if q == h || strings.HasSuffix(q, "."+h) {
		return true
	}
	if strings.HasPrefix(h, "www.") {
		apex := strings.TrimPrefix(h, "www.")
		if apex != "" && (q == apex || strings.HasSuffix(q, "."+apex)) {
			return true
		}
	}
	return false
}

type guestAllowEntry struct {
	IP        string
	AllowHost string
}

func guestAllow(root, guestIP string) (vm, host string, ok bool) {
	all, err := readAllowGuests(root)
	if err != nil {
		log.Printf("read allow table: %v", err)
		return "", "", false
	}
	for name, ent := range all {
		if ent.IP == guestIP && ent.AllowHost != "" {
			return name, ent.AllowHost, true
		}
	}
	return "", "", false
}

func readAllowGuests(root string) (map[string]guestAllowEntry, error) {
	b, err := os.ReadFile(filepath.Join(root, "allow-net.json"))
	if err != nil {
		return nil, err
	}
	var raw struct {
		Hosts map[string]json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]guestAllowEntry, len(raw.Hosts))
	for name, msg := range raw.Hosts {
		msg = bytesTrim(msg)
		if len(msg) == 0 {
			continue
		}
		if msg[0] == '"' {
			var ip string
			if err := json.Unmarshal(msg, &ip); err != nil {
				return nil, err
			}
			out[name] = guestAllowEntry{IP: ip}
			continue
		}
		var ent struct {
			IP        string `json:"ip"`
			AllowHost string `json:"allowHost"`
		}
		if err := json.Unmarshal(msg, &ent); err != nil {
			return nil, err
		}
		out[name] = guestAllowEntry{IP: ent.IP, AllowHost: ent.AllowHost}
	}
	return out, nil
}

var (
	allowMu     sync.Mutex
	allowOpened = map[string]map[string]struct{}{}
)

func ensureAllow(vm string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	allowMu.Lock()
	defer allowMu.Unlock()
	known := allowOpened[vm]
	if known == nil {
		known = map[string]struct{}{}
		allowOpened[vm] = known
	}
	var need []string
	for _, ip := range ips {
		if _, ok := known[ip]; !ok {
			need = append(need, ip)
		}
	}
	if len(need) == 0 {
		return nil
	}
	if err := AddAllowIPs(vm, need); err != nil {
		return err
	}
	for _, ip := range need {
		known[ip] = struct{}{}
	}
	return nil
}

var (
	upstreamOnce sync.Once
	upstreamList []string
)

// ResolveIPv4 looks up host through the DNS servers on the default-route
// interface. The Windows resolver asks every adapter, and the Hyper-V
// default switch answers public names with 10.0.0.1.
func ResolveIPv4(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, fmt.Errorf("%s is not an IPv4 address", host)
		}
		return []net.IP{ip.To4()}, nil
	}
	ips, err := lookupA(host)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return ips, nil
}

func lookupA(name string) ([]net.IP, error) {
	abs := strings.TrimSuffix(name, ".") + "."
	var last error
	for _, up := range upstreamDNS() {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				d.Timeout = 3 * time.Second
				return d.DialContext(ctx, "udp", net.JoinHostPort(up, "53"))
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := resolver.LookupIP(ctx, "ip4", abs)
		cancel()
		if err == nil {
			return ips, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no upstream dns")
	}
	return nil, last
}

func upstreamDNS() []string {
	upstreamOnce.Do(func() {
		cmd := command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; if ($route) { Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } }`)
		out, err := cmd.Output()
		if err == nil {
			for _, line := range strings.Fields(string(out)) {
				ip := net.ParseIP(line)
				if ip == nil || ip.To4() == nil || ip.IsLoopback() || strings.HasPrefix(line, "172.29.248.") {
					continue
				}
				upstreamList = append(upstreamList, line)
			}
		}
		if len(upstreamList) == 0 {
			upstreamList = []string{"1.1.1.1", "8.8.8.8"}
		}
	})
	return upstreamList
}

func firstQuestion(msg []byte) (string, uint16, error) {
	if len(msg) < 12 {
		return "", 0, errors.New("short dns message")
	}
	if binary.BigEndian.Uint16(msg[4:6]) < 1 {
		return "", 0, errors.New("dns message has no question")
	}
	name, off, err := parseDNSName(msg, 12)
	if err != nil {
		return "", 0, err
	}
	if off+4 > len(msg) {
		return "", 0, errors.New("truncated dns question")
	}
	return name, binary.BigEndian.Uint16(msg[off : off+2]), nil
}

func parseDNSName(msg []byte, off int) (string, int, error) {
	var labels []string
	for hops := 0; hops < 10; hops++ {
		if off >= len(msg) {
			return "", 0, errors.New("truncated dns name")
		}
		n := int(msg[off])
		if n == 0 {
			return strings.Join(labels, "."), off + 1, nil
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", 0, errors.New("truncated dns pointer")
			}
			ptr := int(n&0x3F)<<8 | int(msg[off+1])
			rest, _, err := parseDNSName(msg, ptr)
			if err != nil {
				return "", 0, err
			}
			if len(labels) > 0 && rest != "" {
				rest = strings.Join(labels, ".") + "." + rest
			} else if len(labels) > 0 {
				rest = strings.Join(labels, ".")
			}
			return rest, off + 2, nil
		}
		if n&0xC0 != 0 {
			return "", 0, errors.New("unsupported dns label")
		}
		off++
		if off+n > len(msg) {
			return "", 0, errors.New("truncated dns label")
		}
		labels = append(labels, string(msg[off:off+n]))
		off += n
	}
	return "", 0, errors.New("dns name pointer loop")
}

func questionEnd(msg []byte) (int, error) {
	if len(msg) < 12 {
		return 0, errors.New("short dns message")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := parseDNSName(msg, off)
		if err != nil {
			return 0, err
		}
		if next+4 > len(msg) {
			return 0, errors.New("truncated dns question")
		}
		off = next + 4
	}
	return off, nil
}

func dnsHeader(query []byte, ancount, rcode int) []byte {
	end, err := questionEnd(query)
	if err != nil || end > len(query) {
		return nil
	}
	resp := append([]byte(nil), query[:end]...)
	resp[2] = 0x80 | (query[2] & 0x01)
	resp[3] = 0x80 | byte(rcode&0x0F)
	binary.BigEndian.PutUint16(resp[4:6], binary.BigEndian.Uint16(query[4:6]))
	binary.BigEndian.PutUint16(resp[6:8], uint16(ancount))
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

func dnsA(query []byte, ips []net.IP) []byte {
	var v4s []net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			v4s = append(v4s, v4)
		}
	}
	resp := dnsHeader(query, len(v4s), 0)
	if resp == nil {
		return nil
	}
	for _, ip := range v4s {
		resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		resp = append(resp, ip...)
	}
	return resp
}

func ipKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func bytesTrim(b []byte) []byte {
	return bytes.TrimSpace(b)
}
