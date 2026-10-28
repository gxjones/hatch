package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	phaseStarting = "starting" // claimed; the clone is booting under Name
	phaseStarted  = "started"  // clone is up, success not acked
	phaseRunning  = "running"  // success acked; watch the deleted pile
	phaseFailed   = "failed"   // failure not acked; the clone is removed after
	phaseCleanup  = "cleanup"  // failure acked; the clone still has to be removed
)

// healthEvery is how often running clones are checked against Hyper-V.
const healthEvery = time.Minute

// Options selects the queue and how many clones this process will run.
type Options struct {
	Server    string
	Token     string
	OS        string
	Poll      time.Duration
	Max       int
	StatePath string
	Manager   Manager
	// HTTP is optional. Tests inject a client. The worker token is still
	// sent only to Server.
	HTTP *http.Client
	// Health is how often clones are checked against Hyper-V. Zero means healthEvery.
	Health time.Duration
}

type record struct {
	UID   string `json:"uid"`
	OS    string `json:"os,omitempty"`
	Name  string `json:"name,omitempty"`
	ID    string `json:"id,omitempty"`
	URL   string `json:"url,omitempty"`
	Host  string `json:"host,omitempty"`
	Phase string `json:"phase"`
	Error string `json:"error,omitempty"`
}

type stateFile struct {
	VMs []record `json:"vms"`
}

// bootResult carries a finished Start back to the loop. err is already
// redacted, so the WebSocket token never leaves the boot goroutine.
type bootResult struct {
	uid string
	vm  VM
	err string
}

type runner struct {
	ctx        context.Context
	opt        Options
	client     *Client
	recs       []record
	booting    map[string]bool
	results    chan bootResult
	lastHealth time.Time
}

// Run polls the queue until ctx is cancelled. Clones already recorded in
// StatePath keep running across restarts and are destroyed when their uid
// shows up in the deleted pile. Cancel waits for boots in progress, then
// leaves the clones running.
func Run(ctx context.Context, opt Options) error {
	if err := opt.validate(); err != nil {
		return err
	}
	if opt.Health <= 0 {
		opt.Health = healthEvery
	}
	w := &runner{
		ctx: ctx,
		opt: opt,
		client: &Client{
			BaseURL: opt.Server,
			Token:   strings.TrimSpace(opt.Token),
			HTTP:    opt.HTTP,
		},
		booting: map[string]bool{},
		results: make(chan bootResult, opt.Max),
	}
	if err := w.load(); err != nil {
		return err
	}
	// Hyper-V can be unavailable for a while after the host boots.
	for {
		err := w.checkHealth()
		if err == nil {
			break
		}
		log.Printf("worker: check clones: %s", err)
		if !w.sleep() {
			return w.shutdown()
		}
	}
	if n := w.liveCount(); n > 0 {
		log.Printf("worker: tracking %d clone(s)", n)
	}
	for {
		if w.ctx.Err() != nil {
			return w.shutdown()
		}
		w.collect()
		if err := w.reapDeleted(); err != nil {
			if done, ret := w.fail(err); done {
				return ret
			}
			continue
		}
		if err := w.settle(); err != nil {
			if done, ret := w.fail(err); done {
				return ret
			}
			continue
		}
		if time.Since(w.lastHealth) >= w.opt.Health {
			if err := w.checkHealth(); err != nil {
				log.Printf("worker: check clones: %s", err)
			}
		}
		if w.atCapacity() {
			if !w.sleep() {
				return w.shutdown()
			}
			continue
		}
		claimed, err := w.claimOne()
		if err != nil {
			if done, ret := w.fail(err); done {
				return ret
			}
			continue
		}
		if !claimed && !w.sleep() {
			return w.shutdown()
		}
	}
}

func (o Options) validate() error {
	if strings.TrimSpace(o.Token) == "" {
		return errors.New("worker token is required")
	}
	if strings.ContainsAny(o.Token, "\r\n\x00") {
		return errors.New("worker token cannot contain a newline or NUL")
	}
	if strings.TrimSpace(o.OS) == "" {
		return errors.New("os is required")
	}
	if o.Poll <= 0 {
		return errors.New("poll interval must be positive")
	}
	if o.Max <= 0 {
		return errors.New("max clones must be positive")
	}
	if o.Manager == nil {
		return errors.New("manager is required")
	}
	if strings.TrimSpace(o.StatePath) == "" {
		return errors.New("state path is required")
	}
	u, err := url.Parse(strings.TrimSpace(o.Server))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("server URL must be an http or https origin")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return errors.New("server URL must be an origin without a path, query, or userinfo")
	}
	return nil
}

// shutdown waits for boots in progress so their clones are recorded, then
// returns. The next run reports them. Nothing here talks to the queue.
func (w *runner) shutdown() error {
	if n := len(w.booting); n > 0 {
		log.Printf("worker: waiting for %d boot(s) to finish. Press Ctrl+C again to exit now", n)
		for len(w.booting) > 0 {
			w.recordBoot(<-w.results)
		}
	}
	log.Printf("worker: stopping")
	return nil
}

// fail reports err. done means Run should return ret. A rejected token is
// returned to the caller. Cancellation ends the run without an error.
// Anything else is logged and retried after the poll interval.
func (w *runner) fail(err error) (done bool, ret error) {
	if w.ctx.Err() != nil {
		return true, w.shutdown()
	}
	if isAuth(err) {
		return true, err
	}
	log.Printf("worker: %s", err)
	if !w.sleep() {
		return true, w.shutdown()
	}
	return false, nil
}

// soft logs an error that only affects one record, so the others keep
// moving. A rejected token still has to stop the worker.
func (w *runner) soft(err error) error {
	if err == nil || isAuth(err) {
		return err
	}
	log.Printf("worker: %s", err)
	return nil
}

// sleep waits one poll interval. A finished boot ends the wait early so its
// finish is not delayed. It returns false when ctx is cancelled.
func (w *runner) sleep() bool {
	timer := time.NewTimer(w.opt.Poll)
	defer timer.Stop()
	select {
	case <-w.ctx.Done():
		return false
	case r := <-w.results:
		w.handleBoot(r)
		return true
	case <-timer.C:
		return true
	}
}

// collect handles boots that finished since the last pass.
func (w *runner) collect() {
	for {
		select {
		case r := <-w.results:
			w.handleBoot(r)
		default:
			return
		}
	}
}

func (w *runner) atCapacity() bool {
	return len(w.recs) >= w.opt.Max
}

func (w *runner) liveCount() int {
	n := 0
	for _, rec := range w.recs {
		if rec.ID != "" || rec.Name != "" {
			n++
		}
	}
	return n
}

// checkHealth compares the records with Hyper-V. A clone that is gone or
// turned off is reported as failed and removed, which frees its slot. A
// claim with no boot in progress was interrupted and is failed the same way.
func (w *runner) checkHealth() error {
	listed, err := w.opt.Manager.List()
	if err != nil {
		return err
	}
	w.lastHealth = time.Now()
	state := make(map[string]string, len(listed))
	for _, vm := range listed {
		state[vm.ID] = vm.State
	}
	changed := false
	live := 0
	for i := range w.recs {
		rec := &w.recs[i]
		if w.booting[rec.UID] {
			continue
		}
		switch rec.Phase {
		case phaseStarting:
			if rec.ID != "" {
				rec.Phase = phaseStarted
			} else {
				rec.Phase = phaseFailed
				if rec.Error == "" {
					rec.Error = "worker restarted before the clone was ready"
				}
			}
			changed = true
		case phaseStarted, phaseRunning:
			st, ok := state[rec.ID]
			switch {
			case !ok:
				log.Printf("worker: %s (%s) is no longer running", rec.ID, rec.UID)
				rec.Phase = phaseFailed
				rec.Error = "clone is no longer running"
				changed = true
			case strings.EqualFold(st, "Off"):
				log.Printf("worker: %s (%s) is turned off", rec.ID, rec.UID)
				rec.Phase = phaseFailed
				rec.Error = "clone was turned off"
				changed = true
			default:
				live++
			}
		}
	}
	if changed {
		if err := w.save(); err != nil {
			log.Printf("worker: %s", err)
		}
	}
	if live > 0 {
		if m, ok := w.opt.Manager.(maintainer); ok {
			if err := m.Maintain(); err != nil {
				log.Printf("worker: %s", err)
			}
		}
	}
	return nil
}

// reapDeleted asks the queue which tracked clones were deleted and removes
// them. A failure on one clone is logged and retried on the next pass.
func (w *runner) reapDeleted() error {
	var uids []string
	for _, rec := range w.recs {
		if w.booting[rec.UID] {
			continue
		}
		if rec.Phase == phaseStarted || rec.Phase == phaseRunning {
			uids = append(uids, rec.UID)
		}
	}
	if len(uids) == 0 {
		return nil
	}
	gone, err := w.client.Deleted(w.ctx, uids)
	if err != nil {
		return err
	}
	drop := make(map[string]bool, len(gone))
	for _, uid := range gone {
		drop[uid] = true
	}
	for _, rec := range append([]record(nil), w.recs...) {
		if !drop[rec.UID] {
			continue
		}
		if err := w.soft(w.destroy(rec)); err != nil {
			return err
		}
	}
	return nil
}

// destroy removes a clone whose request was deleted. A clone whose success
// was never acked is reported as failed so the request does not stay pending.
func (w *runner) destroy(rec record) error {
	if rec.Phase != phaseRunning {
		rec.Phase = phaseFailed
		rec.Error = "deleted"
		w.update(rec)
		return w.abandon(rec)
	}
	if _, err := w.stop(rec); err != nil {
		return err
	}
	log.Printf("worker: removed %s (%s)", rec.ID, rec.UID)
	return w.drop(rec.UID)
}

// settle retries finishes the queue has not acked and removes failed clones.
// Each record is handled on its own, so one stuck record does not block the rest.
func (w *runner) settle() error {
	for _, rec := range append([]record(nil), w.recs...) {
		if w.booting[rec.UID] {
			continue
		}
		var err error
		switch rec.Phase {
		case phaseStarted:
			err = w.finishStarted(rec)
		case phaseFailed, phaseCleanup:
			err = w.abandon(rec)
		}
		if err := w.soft(err); err != nil {
			return err
		}
	}
	return nil
}

func (w *runner) claimOne() (bool, error) {
	claim, ok, err := w.client.Claim(w.ctx, w.opt.OS)
	if err != nil || !ok {
		return false, err
	}
	if w.has(claim.UID) {
		log.Printf("worker: %s is already tracked", claim.UID)
		return true, nil
	}
	osName := claim.OS
	if osName == "" {
		osName = w.opt.OS
	}
	rec := record{UID: claim.UID, OS: osName, URL: strings.TrimSpace(claim.URL), Phase: phaseStarting}
	name, err := randomName()
	if err != nil {
		rec.Phase = phaseFailed
		rec.Error = "could not choose a clone name: " + err.Error()
		w.recs = append(w.recs, rec)
		return true, w.soft(w.abandon(rec))
	}
	rec.Name = name
	w.recs = append(w.recs, rec)
	if err := w.save(); err != nil {
		// Booting a clone the state file does not know about could leak it.
		rec.Phase = phaseFailed
		rec.Error = "worker could not record the claim: " + err.Error()
		w.update(rec)
		log.Printf("worker: %s %s", claim.UID, rec.Error)
		return true, w.soft(w.abandon(rec))
	}
	log.Printf("worker: claimed %s as %s", claim.UID, name)

	w.booting[claim.UID] = true
	uid, rawURL, token, secret := claim.UID, claim.URL, claim.Token, w.opt.Token
	go func() {
		vm, err := w.opt.Manager.Start(name, rawURL, token)
		res := bootResult{uid: uid, vm: vm}
		if err != nil {
			res.err = cleanErr(err.Error(), token, secret)
			if res.err == "" {
				res.err = "start failed"
			}
		}
		w.results <- res
	}()
	return true, nil
}

// recordBoot saves the outcome of a boot without talking to the queue.
func (w *runner) recordBoot(r bootResult) (record, bool) {
	delete(w.booting, r.uid)
	rec, ok := w.find(r.uid)
	if !ok {
		return record{}, false
	}
	if r.err != "" {
		log.Printf("worker: %s start failed: %s", r.uid, r.err)
		rec.Phase = phaseFailed
		rec.Error = r.err
	} else {
		rec.ID = r.vm.ID
		rec.Host = r.vm.GuestIP
		if r.vm.URL != "" {
			rec.URL = r.vm.URL
		}
		rec.Phase = phaseStarted
		rec.Error = ""
		log.Printf("worker: %s running as %s host %s", r.uid, rec.ID, rec.Host)
	}
	w.update(rec)
	if err := w.save(); err != nil {
		log.Printf("worker: %s", err)
	}
	return rec, true
}

func (w *runner) handleBoot(r bootResult) {
	rec, ok := w.recordBoot(r)
	if !ok {
		return
	}
	if rec.Phase == phaseFailed {
		if err := w.soft(w.abandon(rec)); err != nil {
			log.Printf("worker: %s", err)
		}
		return
	}
	// The user can delete the request while the clone is still booting.
	// Tear it down instead of reporting success.
	gone, err := w.client.Deleted(w.ctx, []string{rec.UID})
	if err != nil {
		log.Printf("worker: %s deleted check: %s", rec.UID, err)
	} else if contains(gone, rec.UID) {
		if err := w.soft(w.destroy(rec)); err != nil {
			log.Printf("worker: %s", err)
		}
		return
	}
	if err := w.soft(w.finishStarted(rec)); err != nil {
		log.Printf("worker: %s", err)
	}
}

func (w *runner) finishStarted(rec record) error {
	if err := w.finishSuccess(rec); err != nil {
		return err
	}
	rec.Phase = phaseRunning
	rec.Error = ""
	w.update(rec)
	return w.save()
}

// abandon reports a failed claim, then removes its clone. The failure is
// sent first so the request does not wait on a slow or stuck removal.
func (w *runner) abandon(rec record) error {
	if rec.Phase != phaseCleanup {
		if err := w.finishFailure(rec, rec.Error); err != nil {
			return err
		}
		rec.Phase = phaseCleanup
		w.update(rec)
		if err := w.save(); err != nil {
			return err
		}
	}
	removed, err := w.stop(rec)
	if err != nil {
		return err
	}
	if removed {
		log.Printf("worker: removed %s (%s)", w.vmName(rec), rec.UID)
	}
	return w.drop(rec.UID)
}

func (w *runner) vmName(rec record) string {
	if rec.ID != "" {
		return rec.ID
	}
	return rec.Name
}

// stop removes the record's clone. A clone that does not exist is already gone.
func (w *runner) stop(rec record) (bool, error) {
	name := w.vmName(rec)
	if name == "" {
		return false, nil
	}
	if _, err := w.opt.Manager.Stop(name); err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("remove %s (%s): %w", name, rec.UID, err)
	}
	return true, nil
}

func (w *runner) finishSuccess(rec record) error {
	body := map[string]any{"status": "success"}
	if rec.ID != "" {
		body["id"] = rec.ID
	}
	if rec.Host != "" {
		body["host"] = rec.Host
	}
	return w.finished(rec, w.client.Finish(w.ctx, w.osOf(rec), rec.UID, body))
}

func (w *runner) finishFailure(rec record, msg string) error {
	if msg == "" {
		msg = "failed"
	}
	return w.finished(rec, w.client.Finish(w.ctx, w.osOf(rec), rec.UID, map[string]any{
		"status": "failure",
		"error":  msg,
	}))
}

// finished treats a finish the queue will never accept as done. Retrying a
// 400 or 409 forever would hold the slot and repeat the same request.
func (w *runner) finished(rec record, err error) error {
	if err == nil {
		return nil
	}
	if isStatus(err, http.StatusNotFound) {
		log.Printf("worker: %s finish was not found", rec.UID)
		return nil
	}
	if isPermanent(err) {
		log.Printf("worker: %s finish was rejected, giving up: %s", rec.UID, err)
		return nil
	}
	return err
}

func (w *runner) osOf(rec record) string {
	if rec.OS != "" {
		return rec.OS
	}
	return w.opt.OS
}

func (w *runner) has(uid string) bool {
	_, ok := w.find(uid)
	return ok
}

func (w *runner) find(uid string) (record, bool) {
	for _, rec := range w.recs {
		if rec.UID == uid {
			return rec, true
		}
	}
	return record{}, false
}

func (w *runner) update(rec record) {
	for i := range w.recs {
		if w.recs[i].UID == rec.UID {
			w.recs[i] = rec
			return
		}
	}
	w.recs = append(w.recs, rec)
}

func (w *runner) remove(uid string) {
	next := make([]record, 0, len(w.recs))
	for _, rec := range w.recs {
		if rec.UID != uid {
			next = append(next, rec)
		}
	}
	w.recs = next
}

// drop forgets uid. The in-memory list is restored if the state file cannot
// be written, so a retry sees the same claim.
func (w *runner) drop(uid string) error {
	prev := append([]record(nil), w.recs...)
	w.remove(uid)
	if err := w.save(); err != nil {
		w.recs = prev
		return err
	}
	return nil
}

func (w *runner) load() error {
	b, err := os.ReadFile(w.opt.StatePath)
	if err != nil {
		if os.IsNotExist(err) {
			w.recs = []record{}
			return nil
		}
		return err
	}
	var file stateFile
	if err := json.Unmarshal(b, &file); err != nil {
		return fmt.Errorf("worker state: %w", err)
	}
	if file.VMs == nil {
		file.VMs = []record{}
	}
	w.recs = file.VMs
	return nil
}

func (w *runner) save() error {
	if w.recs == nil {
		w.recs = []record{}
	}
	b, err := json.MarshalIndent(stateFile{VMs: w.recs}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(w.opt.StatePath), 0o755); err != nil {
		return err
	}
	tmp := w.opt.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, w.opt.StatePath); err == nil {
		return nil
	}
	// Windows will not rename onto an existing file, and a reader or scanner
	// can refuse the delete. Overwrite the destination instead.
	if err := os.WriteFile(w.opt.StatePath, b, 0o644); err != nil {
		return err
	}
	_ = os.Remove(tmp)
	return nil
}

func isAuth(err error) bool {
	return isStatus(err, http.StatusUnauthorized) || isStatus(err, http.StatusForbidden)
}

// isPermanent is a 4xx the queue will return again for the same request.
func isPermanent(err error) bool {
	var hs *httpStatus
	if !errors.As(err, &hs) {
		return false
	}
	switch hs.Code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return hs.Code >= 400 && hs.Code < 500
}

func isStatus(err error, code int) bool {
	var hs *httpStatus
	return errors.As(err, &hs) && hs.Code == code
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func cleanErr(msg string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "[redacted]")
		}
	}
	msg = strings.ReplaceAll(msg, "\r", " ")
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.Join(strings.Fields(msg), " ")
	return clip(msg, 500)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for !utf8.ValidString(cut) && len(cut) > 0 {
		cut = cut[:len(cut)-1]
	}
	return cut
}
