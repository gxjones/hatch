package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hatch/internal/hyperv"
)

const requestTimeout = 30 * time.Second

// Client is the worker half of the queue. Claim takes the oldest queued
// request. Finish merges fields into the object the user reads back.
// Deleted reports which of the given uids are in the deleted pile.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client

	own *http.Client
}

// Claim is one queued VM request. The token is the WebSocket credential
// for that clone and is not stored.
type Claim struct {
	UID    string `json:"uid"`
	OS     string `json:"os"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

type httpStatus struct {
	Op   string
	Code int
}

func (e *httpStatus) Error() string {
	return fmt.Sprintf("%s: HTTP %d", e.Op, e.Code)
}

// Claim fetches the oldest queued request. ok is false when the queue is empty.
// An empty queue is a 204, a 404, or a 200 whose object has no uid.
func (c *Client) Claim(ctx context.Context, osName string) (Claim, bool, error) {
	u, err := c.build("api", "worker", "vm")
	if err != nil {
		return Claim{}, false, err
	}
	if osName != "" {
		q := u.Query()
		q.Set("os", osName)
		u.RawQuery = q.Encode()
	}
	code, body, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Claim{}, false, fmt.Errorf("claim: %w", err)
	}
	if err := httpError("claim", code); err != nil {
		return Claim{}, false, err
	}
	switch code {
	case http.StatusNoContent, http.StatusNotFound:
		return Claim{}, false, nil
	case http.StatusOK:
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			return Claim{}, false, nil
		}
		var claim Claim
		if err := json.Unmarshal(trimmed, &claim); err != nil {
			return Claim{}, false, errors.New("claim response was not a vm object")
		}
		if claim.UID == "" {
			return Claim{}, false, nil
		}
		return claim, true, nil
	default:
		return Claim{}, false, &httpStatus{Op: "claim", Code: code}
	}
}

// Finish reports success or failure. fields are merged into the user-visible
// object. status must already be success or failure.
func (c *Client) Finish(ctx context.Context, osName, uid string, fields map[string]any) error {
	status, _ := fields["status"].(string)
	if status != "success" && status != "failure" {
		return errors.New("finish status must be success or failure")
	}
	u, err := c.build("api", "worker", "vm", osName, uid)
	if err != nil {
		return err
	}
	code, _, err := c.do(ctx, http.MethodPut, u, fields)
	if err != nil {
		return fmt.Errorf("finish %s: %w", uid, err)
	}
	if err := httpError("finish "+uid, code); err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return &httpStatus{Op: "finish " + uid, Code: code}
	}
	return nil
}

// Deleted posts the running uids and returns the subset in the deleted pile.
func (c *Client) Deleted(ctx context.Context, uids []string) ([]string, error) {
	if uids == nil {
		uids = []string{}
	}
	u, err := c.build("api", "worker", "deleted")
	if err != nil {
		return nil, err
	}
	code, body, err := c.do(ctx, http.MethodPost, u, uids)
	if err != nil {
		return nil, fmt.Errorf("deleted: %w", err)
	}
	if err := httpError("deleted", code); err != nil {
		return nil, err
	}
	if code < 200 || code >= 300 {
		return nil, &httpStatus{Op: "deleted", Code: code}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []string{}, nil
	}
	var gone []string
	if err := json.Unmarshal(trimmed, &gone); err != nil {
		return nil, errors.New("deleted response was not a list of uids")
	}
	if gone == nil {
		gone = []string{}
	}
	return gone, nil
}

func httpError(op string, code int) error {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return &httpStatus{Op: op, Code: code}
	}
	return nil
}

func (c *Client) build(elem ...string) (*url.URL, error) {
	base := strings.TrimSpace(c.BaseURL)
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("server URL must be http or https")
	}
	joined, err := url.JoinPath(u.String(), elem...)
	if err != nil {
		return nil, err
	}
	return url.Parse(joined)
}

func (c *Client) do(ctx context.Context, method string, u *url.URL, payload any) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var buf io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), buf)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return res.StatusCode, nil, err
	}
	return res.StatusCode, body, nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	if c.own != nil {
		return c.own
	}
	host := ""
	if u, err := url.Parse(c.BaseURL); err == nil {
		host = u.Host
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialQueue
	c.own = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			if !strings.EqualFold(req.URL.Host, host) {
				return errors.New("redirect left the queue server")
			}
			return nil
		},
	}
	return c.own
}

// dialQueue resolves through the default-route DNS servers. The system
// resolver also asks the Hyper-V default switch, which answers with 10.0.0.1.
func dialQueue(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	ips, err := hyperv.ResolveIPv4(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	for _, ip := range ips {
		if !routableQueueIP(ip) {
			last = fmt.Errorf("dns for %s returned %s", host, ip)
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("dns for %s returned no usable address", host)
	}
	return nil, last
}

func routableQueueIP(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}
