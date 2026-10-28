package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	workerToken = "worker-key"
	wsToken     = "secret-token"
)

type fakeManager struct {
	mu       sync.Mutex
	vms      []VM
	starts   int
	names    []string
	stopped  []string
	startErr error
	stopErr  map[string]error
}

func (f *fakeManager) Start(name, rawURL, token string) (VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	f.names = append(f.names, name)
	if f.startErr != nil {
		return VM{}, f.startErr
	}
	if token == "" || rawURL == "" {
		return VM{}, errors.New("wstoudp needs --ws-url and --ws-token")
	}
	vm := VM{ID: name, State: "Running", URL: rawURL, GuestIP: "172.29.248.10"}
	f.vms = append(f.vms, vm)
	return vm, nil
}

func (f *fakeManager) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

func (f *fakeManager) nameList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.names...)
}

func (f *fakeManager) Stop(id string) (VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, id)
	if err := f.stopErr[id]; err != nil {
		return VM{}, err
	}
	for i, vm := range f.vms {
		if vm.ID == id {
			f.vms = append(f.vms[:i], f.vms[i+1:]...)
			return VM{ID: id, State: "removed"}, nil
		}
	}
	return VM{}, ErrNotFound
}

func (f *fakeManager) List() ([]VM, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.vms == nil {
		return []VM{}, nil
	}
	out := make([]VM, len(f.vms))
	copy(out, f.vms)
	return out, nil
}

func (f *fakeManager) stopCount() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.stopped))
	copy(out, f.stopped)
	return out
}

func TestClaimBootsAndDeletedStops(t *testing.T) {
	mgr := &fakeManager{}
	finishes := make(chan map[string]any, 1)
	inspect := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	var finished atomic.Bool
	var claims atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authed(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/worker/vm":
			if r.URL.Query().Get("os") != "windows" {
				t.Errorf("os query %q", r.URL.Query().Get("os"))
			}
			if claims.Add(1) == 1 {
				writeJSON(w, map[string]any{
					"uid": "uid-1", "os": "windows", "status": "pending",
					"url": "wss://vm.example/wireguard", "token": wsToken,
				})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/api/worker/vm/windows/uid-1":
			body := readMap(t, r)
			if _, ok := body["token"]; ok || bytes.Contains(mustJSON(body), []byte(wsToken)) {
				t.Errorf("finish leaked the websocket token: %#v", body)
			}
			finished.Store(true)
			finishes <- body
			writeJSON(w, map[string]any{"uid": "uid-1"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/worker/deleted":
			var uids []string
			if err := json.NewDecoder(r.Body).Decode(&uids); err != nil {
				t.Errorf("deleted body: %v", err)
			}
			if !finished.Load() {
				writeJSON(w, []string{})
				return
			}
			once.Do(func() { inspect <- struct{}{} })
			<-release
			writeJSON(w, []string{"uid-1"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer closeRelease()
	path := filepath.Join(t.TempDir(), "worker.json")
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{
			Server:    srv.URL + "/",
			Token:     workerToken,
			OS:        "windows",
			Poll:      20 * time.Millisecond,
			Max:       4,
			StatePath: path,
			Manager:   mgr,
		})
	}()

	var finish map[string]any
	select {
	case finish = <-finishes:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for finish")
	}
	id, _ := finish["id"].(string)
	names := mgr.nameList()
	if finish["status"] != "success" || finish["host"] != "172.29.248.10" || id == "" || len(names) != 1 || id != names[0] {
		t.Fatalf("finish %#v names %#v", finish, names)
	}

	select {
	case <-inspect:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for deleted check")
	}
	state, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{wsToken, workerToken} {
		if bytes.Contains(state, []byte(secret)) {
			t.Fatalf("state contains %q: %s", secret, state)
		}
	}
	if !bytes.Contains(state, []byte(`"uid": "uid-1"`)) || !bytes.Contains(state, []byte(`"phase": "running"`)) {
		t.Fatalf("state %s", state)
	}
	closeRelease()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stopped := mgr.stopCount()
		if len(stopped) == 1 && stopped[0] == id {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stopped := mgr.stopCount()
	if len(stopped) != 1 || stopped[0] != id {
		t.Fatalf("stopped %#v", stopped)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestStartFailureIsReportedAndRedacted(t *testing.T) {
	mgr := &fakeManager{startErr: fmt.Errorf("wstoudp failed token=%s", wsToken)}
	finishes := make(chan map[string]any, 1)
	var claims atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authed(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/worker/vm":
			if claims.Add(1) == 1 {
				writeJSON(w, map[string]any{
					"uid": "uid-2", "os": "windows",
					"url": "wss://vm.example/wireguard", "token": wsToken,
				})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/api/worker/vm/windows/uid-2":
			finishes <- readMap(t, r)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/api/worker/deleted":
			writeJSON(w, []string{})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "worker.json")
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, testOpts(srv.URL, path, mgr))
	}()

	var finish map[string]any
	select {
	case finish = <-finishes:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for failure")
	}
	errText, _ := finish["error"].(string)
	if finish["status"] != "failure" || !bytes.Contains([]byte(errText), []byte("[redacted]")) || bytes.Contains([]byte(errText), []byte(wsToken)) {
		t.Fatalf("finish %#v", finish)
	}
	waitUntil(t, stateLacks(path, "uid-2"))
	if b, _ := readState(path); bytes.Contains(b, []byte(wsToken)) {
		t.Fatalf("state contains the websocket token: %s", b)
	}
	// The failed boot's name is removed in case Start left a half-built VM.
	names := mgr.nameList()
	if mgr.startCount() != 1 || len(names) != 1 || len(mgr.stopCount()) != 1 || mgr.stopCount()[0] != names[0] {
		t.Fatalf("starts %d names %#v stopped %#v", mgr.startCount(), names, mgr.stopCount())
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestEmptyQueueDoesNotStart(t *testing.T) {
	mgr := &fakeManager{}
	var claims atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authed(t, w, r) {
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/worker/vm" {
			claims.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, testOpts(srv.URL, filepath.Join(t.TempDir(), "worker.json"), mgr))
	}()
	waitUntil(t, func() bool { return claims.Load() >= 2 })
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if mgr.starts != 0 {
		t.Fatalf("started %d", mgr.starts)
	}
}

func TestUnauthorizedStopsTheWorker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := Run(context.Background(), testOpts(srv.URL, filepath.Join(t.TempDir(), "worker.json"), &fakeManager{}))
	if !isAuth(err) {
		t.Fatalf("err %v", err)
	}
}

func TestMaxSkipsClaim(t *testing.T) {
	mgr := &fakeManager{vms: []VM{{ID: "sbx-old", State: "Running"}}}
	var claims, checks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authed(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/worker/vm":
			claims.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/worker/deleted":
			checks.Add(1)
			var uids []string
			if err := json.NewDecoder(r.Body).Decode(&uids); err != nil {
				t.Errorf("deleted body: %v", err)
			}
			if len(uids) != 1 || uids[0] != "already" {
				t.Errorf("deleted uids %#v", uids)
			}
			writeJSON(w, []string{})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "worker.json")
	if err := os.WriteFile(path, []byte("{\"vms\":[{\"uid\":\"already\",\"os\":\"windows\",\"id\":\"sbx-old\",\"phase\":\"running\"}]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	opts := testOpts(srv.URL, path, mgr)
	opts.Max = 1
	go func() { errCh <- Run(ctx, opts) }()
	waitUntil(t, func() bool { return checks.Load() >= 1 })
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if claims.Load() != 0 {
		t.Fatalf("claimed while at max: %d", claims.Load())
	}
	if mgr.starts != 0 {
		t.Fatalf("started %d", mgr.starts)
	}
}

func TestRestartReportsUnfinishedClaim(t *testing.T) {
	mgr := &fakeManager{}
	finishes := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authed(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/worker/vm":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && r.URL.Path == "/api/worker/vm/windows/uid-9":
			finishes <- readMap(t, r)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "worker.json")
	if err := os.WriteFile(path, []byte("{\"vms\":[{\"uid\":\"uid-9\",\"os\":\"windows\",\"phase\":\"starting\"}]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, testOpts(srv.URL, path, mgr)) }()

	var finish map[string]any
	select {
	case finish = <-finishes:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for restarted failure")
	}
	errText, _ := finish["error"].(string)
	if finish["status"] != "failure" || !bytes.Contains([]byte(errText), []byte("restarted")) {
		t.Fatalf("finish %#v", finish)
	}
	waitUntil(t, stateLacks(path, "uid-9"))
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if mgr.starts != 0 {
		t.Fatalf("started %d", mgr.starts)
	}
}

// queueStub answers the worker API. claims are handed out in order, then the
// queue is empty. Each finish is sent on finishes keyed by uid.
func queueStub(t *testing.T, claims []map[string]any, finishCode map[string]int) (*httptest.Server, chan map[string]any) {
	t.Helper()
	finishes := make(chan map[string]any, 16)
	var next atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authed(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/worker/vm":
			i := int(next.Add(1)) - 1
			if i < len(claims) {
				writeJSON(w, claims[i])
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && len(r.URL.Path) > len("/api/worker/vm/windows/"):
			uid := filepath.Base(r.URL.Path)
			body := readMap(t, r)
			body["uid"] = uid
			finishes <- body
			if code := finishCode[uid]; code != 0 {
				w.WriteHeader(code)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/api/worker/deleted":
			writeJSON(w, []string{})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	return srv, finishes
}

func waitFinish(t *testing.T, finishes chan map[string]any, uid string) map[string]any {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case f := <-finishes:
			if f["uid"] == uid {
				return f
			}
		case <-deadline:
			t.Fatalf("timed out waiting for finish of %s", uid)
		}
	}
}

// readState returns the state file once it parses. The worker may be
// overwriting it at the moment a test reads it.
func readState(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var file stateFile
	if json.Unmarshal(b, &file) != nil {
		return nil, false
	}
	return b, true
}

func stateLacks(path, text string) func() bool {
	return func() bool {
		b, ok := readState(path)
		return ok && !bytes.Contains(b, []byte(text))
	}
}

func writeState(t *testing.T, recs string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "worker.json")
	if err := os.WriteFile(path, []byte(`{"vms":`+recs+"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runWorker(t *testing.T, opts Options) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, opts) }()
	return func() {
		cancel()
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTurnedOffCloneIsFailedAndRemoved(t *testing.T) {
	mgr := &fakeManager{vms: []VM{{ID: "sbx-dead", State: "Off"}}}
	srv, finishes := queueStub(t, nil, nil)
	defer srv.Close()
	path := writeState(t, `[{"uid":"uid-d","os":"windows","id":"sbx-dead","phase":"running"}]`)
	stop := runWorker(t, testOpts(srv.URL, path, mgr))
	defer stop()

	f := waitFinish(t, finishes, "uid-d")
	if f["status"] != "failure" || !bytes.Contains([]byte(f["error"].(string)), []byte("turned off")) {
		t.Fatalf("finish %#v", f)
	}
	waitUntil(t, stateLacks(path, "uid-d"))
	if s := mgr.stopCount(); len(s) != 1 || s[0] != "sbx-dead" {
		t.Fatalf("stopped %#v", s)
	}
}

func TestInterruptedBootRemovesNamedClone(t *testing.T) {
	mgr := &fakeManager{vms: []VM{{ID: "sbx-half", State: "Running"}}}
	srv, finishes := queueStub(t, nil, nil)
	defer srv.Close()
	path := writeState(t, `[{"uid":"uid-n","os":"windows","name":"sbx-half","phase":"starting"}]`)
	stop := runWorker(t, testOpts(srv.URL, path, mgr))
	defer stop()

	f := waitFinish(t, finishes, "uid-n")
	if f["status"] != "failure" {
		t.Fatalf("finish %#v", f)
	}
	waitUntil(t, func() bool {
		s := mgr.stopCount()
		return len(s) == 1 && s[0] == "sbx-half"
	})
}

func TestStuckRemovalDoesNotBlockClaims(t *testing.T) {
	mgr := &fakeManager{
		vms:     []VM{{ID: "sbx-stuck", State: "Running"}},
		stopErr: map[string]error{"sbx-stuck": errors.New("hyper-v down did not finish")},
	}
	srv, finishes := queueStub(t, []map[string]any{
		{"uid": "uid-c", "os": "windows", "url": "wss://vm.example/", "token": wsToken},
	}, nil)
	defer srv.Close()
	path := writeState(t, `[{"uid":"uid-s","os":"windows","id":"sbx-stuck","phase":"cleanup","error":"x"}]`)
	stop := runWorker(t, testOpts(srv.URL, path, mgr))
	defer stop()

	if f := waitFinish(t, finishes, "uid-c"); f["status"] != "success" {
		t.Fatalf("finish %#v", f)
	}
	var b []byte
	waitUntil(t, func() bool {
		var ok bool
		b, ok = readState(path)
		return ok
	})
	if !bytes.Contains(b, []byte("uid-s")) {
		t.Fatalf("stuck clone should stay tracked: %s", b)
	}
}

func TestRejectedFinishIsNotRetriedForever(t *testing.T) {
	mgr := &fakeManager{vms: []VM{{ID: "sbx-a", State: "Running"}}}
	srv, finishes := queueStub(t, []map[string]any{
		{"uid": "uid-b", "os": "windows", "url": "wss://vm.example/", "token": wsToken},
	}, map[string]int{"uid-a": http.StatusBadRequest})
	defer srv.Close()
	path := writeState(t, `[{"uid":"uid-a","os":"windows","id":"sbx-a","phase":"started"}]`)
	stop := runWorker(t, testOpts(srv.URL, path, mgr))
	defer stop()

	waitFinish(t, finishes, "uid-a")
	if f := waitFinish(t, finishes, "uid-b"); f["status"] != "success" {
		t.Fatalf("finish %#v", f)
	}
	time.Sleep(100 * time.Millisecond)
	for {
		select {
		case f := <-finishes:
			if f["uid"] == "uid-a" {
				t.Fatalf("rejected finish was retried: %#v", f)
			}
			continue
		default:
		}
		break
	}
}

func testOpts(server, path string, mgr Manager) Options {
	return Options{
		Server:    server,
		Token:     workerToken,
		OS:        "windows",
		Poll:      20 * time.Millisecond,
		Max:       4,
		StatePath: path,
		Manager:   mgr,
	}
}

func authed(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	if r.Header.Get("Authorization") != "Bearer "+workerToken {
		t.Errorf("authorization %q", r.Header.Get("Authorization"))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func readMap(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read body: %v", err)
		return nil
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Errorf("json: %v %s", err, b)
	}
	return body
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func waitUntil(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}
