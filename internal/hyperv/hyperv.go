package hyperv

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

//go:embed script.ps1
var scriptPS1 string

type Doctor struct {
	Elevated       bool     `json:"elevated"`
	VMMS           string   `json:"vmms"`
	VMCompute      string   `json:"vmcompute"`
	HyperVModule   bool     `json:"hypervModule"`
	HyperVAccess   bool     `json:"hypervAccess"`
	HyperVError    string   `json:"hypervError"`
	WindowsSandbox bool     `json:"windowsSandbox"`
	VMConnect      bool     `json:"vmconnect"`
	Switches       []string `json:"switches"`
}

type Instance struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	MemoryMB int    `json:"memoryMB"`
	CPUs     int    `json:"cpus"`
	Disk     string `json:"disk"`
	Notes    string `json:"notes"`
}

type UpResult struct {
	Name           string         `json:"name"`
	ID             string         `json:"id"`
	State          string         `json:"state"`
	Parent         string         `json:"parent"`
	Disk           string         `json:"disk"`
	MemoryMB       int            `json:"memoryMB"`
	CPUs           int            `json:"cpus"`
	Network        string         `json:"network"`
	Generation     int            `json:"generation"`
	ParentReadOnly bool           `json:"parentReadOnly"`
	Heartbeat      string         `json:"heartbeat"`
	Timings        map[string]int `json:"timings"`
	AllowHost      string         `json:"allowHost,omitempty"`
	AllowIPs       stringList     `json:"allowIPs,omitempty"`
	DNS            stringList     `json:"dns,omitempty"`
	GuestIP        string         `json:"guestIP,omitempty"`
	Gateway        string         `json:"gateway,omitempty"`
	AllowError     string         `json:"allowError,omitempty"`
}

// stringList accepts a JSON string or an array. PowerShell's ConvertTo-Json
// writes a one-element array as a bare string.
type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	if data[0] == '[' {
		var many []string
		if err := json.Unmarshal(data, &many); err != nil {
			return err
		}
		*s = many
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*s = []string{one}
	return nil
}

type Removed struct {
	Name  string   `json:"name"`
	Disks []string `json:"disks"`
}

type DownResult struct {
	Removed []Removed `json:"removed"`
}

type BootstrapResult struct {
	Name  string `json:"name"`
	VHD   string `json:"vhd"`
	ISO   string `json:"iso"`
	State string `json:"state"`
}

type RetireResult struct {
	Name     string `json:"name"`
	Parent   string `json:"parent"`
	ReadOnly bool   `json:"readOnly"`
}

type CheckpointResult struct {
	Name       string `json:"name"`
	Checkpoint string `json:"checkpoint"`
	State      string `json:"state"`
	Resumed    bool   `json:"resumed"`
}

type AdoptResult struct {
	Name     string `json:"name"`
	Parent   string `json:"parent"`
	MemoryMB int    `json:"memoryMB"`
	CPUs     int    `json:"cpus"`
	ReadOnly bool   `json:"readOnly"`
}

type RunResult struct {
	Name    string         `json:"name"`
	PID     int            `json:"pid"`
	Exe     string         `json:"exe"`
	Timings map[string]int `json:"timings"`
}

type RunOptions struct {
	Name         string
	Exe          string
	Arg          string
	Args         []string
	User         string
	Password     string
	TimeoutSec   int
	GuestIP      string
	GuestPrefix  int
	GuestGateway string
	GuestDNS     string
}

type UpOptions struct {
	Name          string
	Parent        string
	Diff          string
	MemoryMB      int
	CPUs          int
	Network       string
	Generation    int
	DataRoot      string
	WaitReady     bool
	ReadyTimeout  int
	AllowHost     string
	BiosGUID      string
	BiosSerial    string
	BoardSerial   string
	ChassisSerial string
	ChassisAsset  string
	// DeferGuestNet leaves the planned allow address unset. The caller applies
	// it in the same PowerShell Direct session that starts the guest program.
	DeferGuestNet bool
}

type SealResult struct {
	Name          string `json:"name"`
	Parent        string `json:"parent"`
	MemoryMB      int    `json:"memoryMB"`
	CPUs          int    `json:"cpus"`
	BiosGUID      string `json:"biosGuid"`
	BiosSerial    string `json:"biosSerial"`
	BoardSerial   string `json:"boardSerial"`
	ChassisSerial string `json:"chassisSerial"`
	ChassisAsset  string `json:"chassisAsset"`
	ReadOnly      bool   `json:"readOnly"`
}

func DoctorReport() (Doctor, error) {
	var d Doctor
	err := call("doctor", map[string]string{}, &d)
	return d, err
}

func List() ([]Instance, error) {
	var wrap struct {
		Instances []Instance `json:"instances"`
	}
	if err := call("list", nil, &wrap); err != nil {
		return nil, err
	}
	return wrap.Instances, nil
}

func Up(opts UpOptions) (UpResult, error) {
	env := map[string]string{
		"SBX_NAME":           opts.Name,
		"SBX_PARENT":         opts.Parent,
		"SBX_DIFF":           opts.Diff,
		"SBX_MEM_MB":         fmt.Sprint(opts.MemoryMB),
		"SBX_CPUS":           fmt.Sprint(opts.CPUs),
		"SBX_NETWORK":        opts.Network,
		"SBX_GENERATION":     fmt.Sprint(opts.Generation),
		"SBX_ROOT":           opts.DataRoot,
		"SBX_BIOS_GUID":      opts.BiosGUID,
		"SBX_BIOS_SERIAL":    opts.BiosSerial,
		"SBX_BOARD_SERIAL":   opts.BoardSerial,
		"SBX_CHASSIS_SERIAL": opts.ChassisSerial,
		"SBX_CHASSIS_ASSET":  opts.ChassisAsset,
	}
	if opts.AllowHost != "" {
		env["SBX_ALLOW_HOST"] = opts.AllowHost
	}
	if exe, err := os.Executable(); err == nil {
		env["SBX_EXE"] = exe
	}
	if opts.WaitReady || opts.Network == "allow" {
		env["SBX_WAIT_READY"] = "1"
		timeout := opts.ReadyTimeout
		if timeout <= 0 {
			timeout = 180
		}
		env["SBX_READY_TIMEOUT"] = fmt.Sprint(timeout)
	}
	if opts.DeferGuestNet {
		env["SBX_DEFER_GUEST_NET"] = "1"
	}
	var res UpResult
	err := call("up", env, &res)
	return res, err
}

func Down(name, dataRoot string) (DownResult, error) {
	var res DownResult
	err := call("down", map[string]string{
		"SBX_NAME": name,
		"SBX_ROOT": dataRoot,
	}, &res)
	return res, err
}

func DownAll(dataRoot string) (DownResult, error) {
	var res DownResult
	err := call("down", map[string]string{
		"SBX_ALL":  "1",
		"SBX_ROOT": dataRoot,
	}, &res)
	return res, err
}

func Bootstrap(name, vhd, iso, network, dataRoot string, memoryMB, cpus int, sizeGB int) (BootstrapResult, error) {
	var res BootstrapResult
	err := call("bootstrap", map[string]string{
		"SBX_NAME":    name,
		"SBX_PARENT":  vhd,
		"SBX_ISO":     iso,
		"SBX_NETWORK": network,
		"SBX_MEM_MB":  fmt.Sprint(memoryMB),
		"SBX_CPUS":    fmt.Sprint(cpus),
		"SBX_SIZE_GB": fmt.Sprint(sizeGB),
		"SBX_ROOT":    dataRoot,
	}, &res)
	return res, err
}

func Retire(name string) (RetireResult, error) {
	var res RetireResult
	err := call("retire", map[string]string{"SBX_NAME": name}, &res)
	return res, err
}

func Seal(name, dest, dataRoot string) (SealResult, error) {
	var res SealResult
	err := call("seal", map[string]string{
		"SBX_NAME":   name,
		"SBX_PARENT": dest,
		"SBX_ROOT":   dataRoot,
	}, &res)
	return res, err
}

func Save(name string) (CheckpointResult, error) {
	var res CheckpointResult
	err := call("save", map[string]string{"SBX_NAME": name}, &res)
	return res, err
}

func Reset(name string) (CheckpointResult, error) {
	var res CheckpointResult
	err := call("reset", map[string]string{"SBX_NAME": name}, &res)
	return res, err
}

func Run(opts RunOptions) (RunResult, error) {
	if err := ValidateName(opts.Name); err != nil {
		return RunResult{}, err
	}
	if strings.TrimSpace(opts.User) == "" {
		return RunResult{}, fmt.Errorf("guest user is empty")
	}
	if strings.ContainsAny(opts.User, "\r\n\x00") || strings.ContainsAny(opts.Password, "\r\n\x00") {
		return RunResult{}, fmt.Errorf("guest user and password cannot contain a newline or NUL")
	}
	// The argument can be kilobytes. A file keeps it out of the environment
	// block, which CreateProcess limits to 32767 characters.
	line, err := commandLineFor(opts.Exe, opts.Arg, opts.Args)
	if err != nil {
		return RunResult{}, err
	}
	f, err := os.CreateTemp("", "hatch-cmd-*.txt")
	if err != nil {
		return RunResult{}, err
	}
	cmdPath := f.Name()
	defer os.Remove(cmdPath)
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return RunResult{}, err
	}
	if err := f.Close(); err != nil {
		return RunResult{}, err
	}
	timeout := opts.TimeoutSec
	if timeout <= 0 {
		timeout = 180
	}
	env := map[string]string{
		"SBX_NAME":           opts.Name,
		"SBX_GUEST_EXE":      opts.Exe,
		"SBX_CMDLINE_FILE":   cmdPath,
		"SBX_WORK_DIR":       guestWorkDir(opts.Exe),
		"SBX_GUEST_USER":     opts.User,
		"SBX_GUEST_PASSWORD": opts.Password,
		"SBX_RUN_TIMEOUT":    fmt.Sprint(timeout),
	}
	if opts.GuestIP != "" {
		if err := validateIPv4(opts.GuestIP); err != nil {
			return RunResult{}, fmt.Errorf("guest IP: %w", err)
		}
		if err := validateIPv4(opts.GuestGateway); err != nil {
			return RunResult{}, fmt.Errorf("guest gateway: %w", err)
		}
		if err := validateIPv4(opts.GuestDNS); err != nil {
			return RunResult{}, fmt.Errorf("guest DNS: %w", err)
		}
		prefix := opts.GuestPrefix
		if prefix == 0 {
			prefix = 24
		}
		if prefix != 24 {
			return RunResult{}, fmt.Errorf("guest prefix %d is not supported", prefix)
		}
		env["SBX_GUEST_IP"] = opts.GuestIP
		env["SBX_GUEST_PREFIX"] = fmt.Sprint(prefix)
		env["SBX_GUEST_GATEWAY"] = opts.GuestGateway
		env["SBX_GUEST_DNS"] = opts.GuestDNS
	}
	var res RunResult
	err = call("run", env, &res)
	return res, err
}

func validateIPv4(s string) error {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("%q is not an IPv4 address", s)
	}
	return nil
}

func Adopt(name, dest, dataRoot string) (AdoptResult, error) {
	var res AdoptResult
	err := call("adopt", map[string]string{
		"SBX_NAME":   name,
		"SBX_PARENT": dest,
		"SBX_ROOT":   dataRoot,
	}, &res)
	return res, err
}

// callTimeouts bound the actions the queue worker uses. A hung PowerShell or
// Hyper-V cmdlet would otherwise stall the worker indefinitely. "up" covers the
// guest heartbeat wait and guest network setup. "run" covers sign-in retries.
var callTimeouts = map[string]time.Duration{
	"up":        15 * time.Minute,
	"run":       10 * time.Minute,
	"down":      5 * time.Minute,
	"list":      2 * time.Minute,
	"allow-acl": 2 * time.Minute,
	"doctor":    2 * time.Minute,
}

func call(action string, extra map[string]string, dest any) error {
	script, err := os.CreateTemp("", "hatch-hv-*.ps1")
	if err != nil {
		return err
	}
	scriptPath := script.Name()
	defer os.Remove(scriptPath)
	if _, err := script.WriteString(scriptPS1); err != nil {
		script.Close()
		return err
	}
	if err := script.Close(); err != nil {
		return err
	}

	ctx := context.Background()
	if limit, ok := callTimeouts[action]; ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	cmd := command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath)
	cmd.Env = append(os.Environ(), "SBX_ACTION="+action)
	for k, v := range extra {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// The DNS proxy started by "up" outlives PowerShell and can inherit its
	// output pipe. Without a delay, Run waits for that pipe until the proxy exits.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	stopTimer := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
	runErr := cmd.Wait()
	stopTimer()
	if errors.Is(runErr, exec.ErrWaitDelay) {
		runErr = nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("hyper-v %s did not finish within %s and was stopped", action, callTimeouts[action])
	}
	line := lastLine(stdout.String())
	if strings.HasPrefix(line, "ERR:") {
		return fmt.Errorf("%s", strings.TrimPrefix(line, "ERR:"))
	}
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = line
		}
		if msg == "" {
			msg = runErr.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	if line == "" {
		return fmt.Errorf("hyper-v returned no result")
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return fmt.Errorf("decode hyper-v result: %w (%s)", err, line)
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("parse hyper-v result: %w (%s)", err, raw)
	}
	return nil
}

// command starts a process with no console of its own. Hyper-V teardown kills
// the DNS proxy, and a console child shares the worker's stop signal.
func command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x08000000, // CREATE_NO_WINDOW
	}
	return cmd
}

func lastLine(s string) string {
	lines := strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' })
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}
