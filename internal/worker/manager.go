package worker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"hatch/internal/config"
	"hatch/internal/hyperv"
	"hatch/internal/winutil"
)

const (
	guestUser     = "User"
	guestPassword = "Rdp-test-1"
	readyTimeout  = 180
)

// ErrNotFound is returned when the id is not one of this tool's VMs.
var ErrNotFound = errors.New("vm not found")

// VM is one throwaway clone. The token used to start it is not kept.
type VM struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	URL     string `json:"url,omitempty"`
	GuestIP string `json:"guestIP,omitempty"`
}

// Manager starts and stops the WireGuard proxy clones. Start creates the
// clone under name, which the worker records before the boot begins so a
// crash mid-boot cannot leave a VM nobody owns.
type Manager interface {
	Start(name, rawURL, token string) (VM, error)
	Stop(id string) (VM, error)
	List() ([]VM, error)
}

// maintainer is optional. Maintain repairs host services that running
// clones depend on.
type maintainer interface {
	Maintain() error
}

// HyperV starts a sealed clone, lets it reach only the WebSocket host on
// TCP 443, and runs wstoudp with the caller's URL and token.
type HyperV struct{}

func (HyperV) Maintain() error {
	return hyperv.EnsureAllowDNS()
}

func (HyperV) Start(name, rawURL, token string) (VM, error) {
	if err := hyperv.ValidateName(name); err != nil {
		return VM{}, err
	}
	launch, err := hyperv.ResolveWstoudpLaunch(rawURL, token, "", guestUser, guestPassword, readyTimeout)
	if err != nil {
		return VM{}, err
	}
	host, err := websocketHost(rawURL)
	if err != nil {
		return VM{}, err
	}
	if err := hyperv.ValidateAllowHost(host); err != nil {
		return VM{}, err
	}
	if err := requireHyperV(); err != nil {
		return VM{}, err
	}
	cfg, err := config.Load()
	if err != nil {
		return VM{}, err
	}
	parent, err := resolveParent(cfg)
	if err != nil {
		return VM{}, err
	}
	mem, cpus := 2048, 2
	if cfg.Resume {
		if cfg.MemoryMB > 0 {
			mem = cfg.MemoryMB
		}
		if cfg.CPUs > 0 {
			cpus = cfg.CPUs
		}
	}
	opts := hyperv.UpOptions{
		Name:          name,
		Parent:        parent,
		Diff:          filepath.Join(config.DataRoot(), "disks", name+".vhdx"),
		MemoryMB:      mem,
		CPUs:          cpus,
		Network:       "allow",
		Generation:    2,
		DataRoot:      config.DataRoot(),
		WaitReady:     true,
		ReadyTimeout:  readyTimeout,
		AllowHost:     host,
		DeferGuestNet: true,
	}
	if cfg.Sealed && cfg.BiosGUID != "" {
		opts.BiosGUID = cfg.BiosGUID
		opts.BiosSerial = cfg.BiosSerial
		opts.BoardSerial = cfg.BoardSerial
		opts.ChassisSerial = cfg.ChassisSerial
		opts.ChassisAsset = cfg.ChassisAsset
	}
	res, err := hyperv.Up(opts)
	if err != nil {
		return VM{}, err
	}
	if res.AllowError != "" {
		_, _ = hyperv.Down(res.Name, config.DataRoot())
		return VM{}, errors.New(res.AllowError)
	}
	if res.GuestIP == "" || res.Gateway == "" {
		_, _ = hyperv.Down(res.Name, config.DataRoot())
		return VM{}, fmt.Errorf("allow network did not assign a guest address")
	}
	dns := res.Gateway
	if len(res.DNS) > 0 && res.DNS[0] != "" {
		dns = res.DNS[0]
	}
	runRes, err := hyperv.Run(hyperv.RunOptions{
		Name:         res.Name,
		Exe:          launch.Exe,
		Args:         launch.Args,
		User:         launch.User,
		Password:     launch.Password,
		TimeoutSec:   launch.Timeout,
		GuestIP:      res.GuestIP,
		GuestGateway: res.Gateway,
		GuestDNS:     dns,
	})
	logBoot(name, res.Timings, runRes.Timings)
	if err != nil {
		_, _ = hyperv.Down(res.Name, config.DataRoot())
		return VM{}, fmt.Errorf("start wstoudp: %w", err)
	}
	return VM{ID: res.Name, State: res.State, URL: strings.TrimSpace(rawURL), GuestIP: res.GuestIP}, nil
}

func logBoot(name string, up, run map[string]int) {
	log.Printf("worker: %s boot disk=%s create=%s start=%s heartbeat=%s hyperv-net=%s psdirect=%s guest-ip=%s attempts=%s",
		name,
		bootMS(up, "differencing_disk_ms"),
		bootMS(up, "create_vm_ms"),
		bootMS(up, "start_vm_ms"),
		bootMS(up, "heartbeat_ms"),
		bootMS(up, "guest_net_ms"),
		bootMS(run, "guest_cmd_ms"),
		bootMS(run, "guest_net_ms"),
		bootMS(run, "guest_cmd_attempts"),
	)
}

func bootMS(m map[string]int, key string) string {
	v, ok := m[key]
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%d", v)
}

func (HyperV) Stop(id string) (VM, error) {
	if err := hyperv.ValidateName(id); err != nil {
		return VM{}, err
	}
	if err := requireHyperV(); err != nil {
		return VM{}, err
	}
	if _, err := hyperv.Down(id, config.DataRoot()); err != nil {
		if strings.Contains(err.Error(), "VM not found") {
			return VM{}, ErrNotFound
		}
		return VM{}, err
	}
	return VM{ID: id, State: "removed"}, nil
}

func (HyperV) List() ([]VM, error) {
	if err := requireHyperV(); err != nil {
		return nil, err
	}
	all, err := hyperv.List()
	if err != nil {
		return nil, err
	}
	out := []VM{}
	for _, vm := range all {
		if vm.Notes != "hyper-v-sandbox throwaway" {
			continue
		}
		out = append(out, VM{ID: vm.Name, State: vm.State})
	}
	return out, nil
}

func websocketHost(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("url must be a ws:// or wss:// URL")
	}
	if port := u.Port(); port != "" && port != "443" && port != "80" {
		return "", fmt.Errorf("url port %s is not reachable; the guest may open TCP 443 only", port)
	}
	return u.Hostname(), nil
}

func resolveParent(cfg config.File) (string, error) {
	if cfg.ParentVHD == "" {
		return "", fmt.Errorf("no parent VHD is configured")
	}
	abs, err := filepath.Abs(cfg.ParentVHD)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("parent VHD: %w", err)
	}
	return abs, nil
}

func requireHyperV() error {
	if winutil.IsElevated() || winutil.InHyperVAdministrators() {
		return nil
	}
	return fmt.Errorf("Hyper-V management needs membership in Hyper-V Administrators, or an elevated process")
}

func randomName() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sbx-" + hex.EncodeToString(b[:]), nil
}
