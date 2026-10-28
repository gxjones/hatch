package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"hatch/internal/config"
	"hatch/internal/hyperv"
	"hatch/internal/winutil"
	"hatch/internal/worker"
	"hatch/internal/wsb"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "doctor":
		err = cmdDoctor()
	case "allow-dns":
		err = hyperv.RunAllowDNS(config.DataRoot())
	case "wsb":
		err = cmdWSB(os.Args[2:])
	case "hv":
		err = cmdHV(os.Args[2:])
	case "worker":
		err = cmdWorker(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `hatch starts throwaway Windows VMs.

Windows Sandbox (one instance, no image to build, desktop in a few seconds):
  hatch wsb
  hatch wsb --no-network --map C:\lab --command "notepad.exe"

Hyper-V differencing clones (many at once, needs one golden VHDX):
  hatch doctor
  hatch hv bootstrap --iso D:\Win11.iso
  hatch hv retire gold
  hatch hv up
  hatch hv up --network private --connect
  hatch hv up --network allow --allow-host example.com
  hatch hv up --network default --ws-url wss://example/ --ws-token TOKEN
  hatch hv list
  hatch hv run sbx-1a2b3c4d --exe C:\lab\feed.exe --arg-file payload.txt
  hatch hv run sbx-1a2b3c4d --ws-url wss://example/ --ws-token TOKEN
  hatch hv seal sbx-1a2b3c4d
  hatch hv save sbx-1a2b3c4d
  hatch hv reset sbx-1a2b3c4d
  hatch hv down sbx-1a2b3c4d
  hatch hv down --all
  hatch worker --token <worker-key>

Hyper-V commands need Hyper-V Administrators in this logon token, or an
elevated terminal. A normal Administrators token is filtered and Hyper-V
rejects it. Windows Sandbox does not need either.

Why both exist:
  Windows Sandbox boots fast because it shares the host's immutable OS files.
  Microsoft exposes that as one .wsb config file and one running instance.
  There is no supported API for a second concurrent Sandbox.
  Differencing disks are the supported way to fork many throwaway Hyper-V VMs.
  Creating the child disk is milliseconds. The first boot of a new machine
  installs devices and sits on the Hyper-V logo. After that desktop is ready,
  "hatch hv seal <name>" keeps the disk. Later clones copy its firmware
  identity, so Windows cold-boots as the same machine.
`)
}

func cmdDoctor() error {
	rep, err := hyperv.DoctorReport()
	if err != nil {
		return err
	}
	yn := func(v bool) string {
		if v {
			return "yes"
		}
		return "no"
	}
	fmt.Printf("elevated token:    %s\n", yn(rep.Elevated || winutil.IsElevated()))
	fmt.Printf("Hyper-V admins:    %s\n", yn(winutil.InHyperVAdministrators()))
	fmt.Printf("vmms:              %s\n", rep.VMMS)
	fmt.Printf("vmcompute:         %s\n", rep.VMCompute)
	fmt.Printf("Hyper-V module:    %s\n", yn(rep.HyperVModule))
	fmt.Printf("Hyper-V access:    %s\n", yn(rep.HyperVAccess))
	if rep.HyperVError != "" {
		fmt.Printf("  %s\n", strings.TrimSpace(rep.HyperVError))
	}
	if len(rep.Switches) > 0 {
		fmt.Printf("switches:          %s\n", strings.Join(rep.Switches, ", "))
	}
	fmt.Printf("Windows Sandbox:   %s\n", yn(rep.WindowsSandbox))
	fmt.Printf("vmconnect:         %s\n", yn(rep.VMConnect))
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.ParentVHD != "" {
		fmt.Printf("parent VHD:        %s\n", cfg.ParentVHD)
	} else {
		fmt.Printf("parent VHD:        (not set)\n")
	}
	if cfg.Resume {
		fmt.Printf("resume:            %d MB, %d CPUs\n", cfg.MemoryMB, cfg.CPUs)
	}
	if cfg.Sealed {
		fmt.Printf("sealed identity:   %s\n", cfg.BiosGUID)
	}
	fmt.Printf("clone disks:       %s\n", filepath.Join(config.DataRoot(), "disks"))
	if !rep.HyperVAccess {
		fmt.Println("\nHyper-V create/start needs Hyper-V Administrators in this logon token, or an elevated terminal (Run as administrator).")
	}
	if rep.WindowsSandbox {
		fmt.Println("\nStart a disposable desktop now:  hatch wsb")
	}
	return nil
}

func cmdWSB(args []string) error {
	fs := flag.NewFlagSet("wsb", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	mem := fs.Int("memory-mb", 4096, "sandbox memory in MB (0 leaves the Sandbox default)")
	noNet := fs.Bool("no-network", false, "disable networking")
	noGPU := fs.Bool("no-gpu", false, "disable vGPU")
	noClip := fs.Bool("no-clipboard", false, "disable clipboard redirection")
	noAudio := fs.Bool("no-audio", false, "disable microphone redirection")
	protected := fs.Bool("protected", false, "enable protected client")
	host := fs.String("map", "", "host folder to map into the sandbox")
	guest := fs.String("map-to", "", "path inside the sandbox (optional)")
	writable := fs.Bool("writable", false, "map the host folder read-write")
	command := fs.String("command", "", "command to run after logon")
	wait := fs.Bool("wait", false, "block until the Sandbox process exits")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: hatch wsb [flags]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *host != "" {
		info, err := os.Stat(*host)
		if err != nil {
			return fmt.Errorf("map folder: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("map folder is not a directory: %s", *host)
		}
	}
	opts := wsb.Options{
		MemoryMB:     *mem,
		Networking:   !*noNet,
		GPU:          !*noGPU,
		AudioInput:   !*noAudio,
		VideoInput:   false,
		Protected:    *protected,
		Printers:     false,
		Clipboard:    !*noClip,
		HostFolder:   *host,
		GuestFolder:  *guest,
		MapReadOnly:  *host != "" && !*writable,
		LogonCommand: *command,
	}
	if err := wsb.CheckRunning(); err != nil {
		return err
	}
	path, err := wsb.Write(filepath.Join(config.Dir(), "wsb"), opts)
	if err != nil {
		return err
	}
	fmt.Printf("config: %s\n", path)
	fmt.Println("launching Windows Sandbox")
	return wsb.Launch(path, *wait)
}

func cmdWorker(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	token := fs.String("token", "", "worker API key; WORKER_API_KEY is used when this is empty")
	serverURL := fs.String("server", "https://t6.staticlightlabs.com", "queue origin")
	osName := fs.String("os", "windows", "operating system to claim")
	poll := fs.Duration("poll", 5*time.Second, "how often to poll when idle")
	max := fs.Int("max", 4, "maximum clones running at once")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: hatch worker --token <worker-key>\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	key := strings.TrimSpace(*token)
	if key == "" {
		key = strings.TrimSpace(os.Getenv("WORKER_API_KEY"))
	}
	if key == "" {
		return fmt.Errorf("pass --token or set WORKER_API_KEY")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if err := lockWorker(); err != nil {
		return err
	}
	fmt.Printf("worker: %s  os=%s  poll=%s  max=%d\n", *serverURL, *osName, poll.String(), *max)
	// Console-close and break events also arrive when a child process, such as
	// the DNS proxy, is destroyed. Those must not end the poll loop. Ctrl+C still does.
	ignoreConsoleClose()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		// After the first Ctrl+C the worker waits for boots in progress.
		// Restoring the default handler lets a second Ctrl+C exit at once.
		<-ctx.Done()
		stop()
	}()
	return worker.Run(ctx, worker.Options{
		Server:    *serverURL,
		Token:     key,
		OS:        *osName,
		Poll:      *poll,
		Max:       *max,
		StatePath: filepath.Join(config.Dir(), "worker.json"),
		Manager:   worker.HyperV{},
	})
}

// workerMutex is held for the life of the process. Two workers would
// overwrite each other's worker.json and claim more clones than --max.
var workerMutex uintptr

func lockWorker() error {
	name, err := syscall.UTF16PtrFromString(`Global\hyper-v-sandbox-worker`)
	if err != nil {
		return err
	}
	h, _, callErr := syscall.NewLazyDLL("kernel32.dll").NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return fmt.Errorf("worker lock: %v", callErr)
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == syscall.ERROR_ALREADY_EXISTS {
		syscall.CloseHandle(syscall.Handle(h))
		return fmt.Errorf("another hatch worker is already running on this PC")
	}
	workerMutex = h
	return nil
}

// consoleCloseCallback stays allocated so Windows can call it for the life of the process.
var consoleCloseCallback uintptr

func ignoreConsoleClose() {
	consoleCloseCallback = syscall.NewCallback(func(ctrl uintptr) uintptr {
		switch ctrl {
		case 1, 2: // CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT
			return 1
		default:
			return 0
		}
	})
	r, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler").Call(consoleCloseCallback, 1)
	if r == 0 {
		fmt.Fprintf(os.Stderr, "worker: console handler: %v\n", err)
	}
}

func cmdHV(args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: hatch hv <up|down|list|connect|run|seal|save|reset|bootstrap|retire|parent|adopt>\n")
		return fmt.Errorf("missing hv subcommand")
	}
	switch args[0] {
	case "up":
		return cmdUp(args[1:])
	case "down":
		return cmdDown(args[1:])
	case "list":
		return cmdList()
	case "connect":
		return cmdConnect(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "bootstrap":
		return cmdBootstrap(args[1:])
	case "retire":
		return cmdRetire(args[1:])
	case "parent":
		return cmdParent(args[1:])
	case "seal":
		return cmdSeal(args[1:])
	case "save":
		return cmdSave(args[1:])
	case "reset":
		return cmdReset(args[1:])
	case "adopt":
		return cmdAdopt(args[1:])
	default:
		return fmt.Errorf("unknown hv subcommand %q", args[0])
	}
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parent := fs.String("parent", "", "parent VHDX (default: the path saved by retire or parent set)")
	name := fs.String("name", "", "VM name (default: sbx- plus random hex)")
	mem := fs.Int("memory-mb", 2048, "maximum memory in MB; idle guests can shrink toward 1536")
	cpus := fs.Int("cpus", 2, "virtual processors")
	network := fs.String("network", "none", "none, private, default, or allow")
	allowHost := fs.String("allow-host", "", "with --network allow, the only host the guest may reach on TCP 443")
	gen := fs.Int("generation", 2, "Hyper-V generation (2 for UEFI Windows)")
	connect := fs.Bool("connect", false, "open vmconnect after start")
	waitReady := fs.Bool("wait-ready", false, "wait until the guest integration heartbeat is OK")
	readyTimeout := fs.Int("ready-timeout", 180, "heartbeat timeout in seconds")
	guest := bindGuestRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	runTimeout := guest.timeout
	if !flagPassed(fs, "run-timeout") {
		runTimeout = *readyTimeout
	}
	if runTimeout <= 0 {
		runTimeout = 180
	}
	launch, err := resolveLaunch(fs, guest, runTimeout)
	if err != nil {
		return err
	}
	if launch != nil && launch.Exe == hyperv.WstoudpExe && *network == "none" {
		return fmt.Errorf("--ws-url needs a network path out of the guest. Use --network default, or --network allow --allow-host <websocket-host>")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	resume := *parent == "" && cfg.Resume
	sealed := *parent == "" && cfg.Sealed && cfg.BiosGUID != ""
	if resume {
		memSet, cpuSet := false, false
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "memory-mb":
				memSet = true
			case "cpus":
				cpuSet = true
			}
		})
		if memSet && *mem != cfg.MemoryMB {
			return fmt.Errorf("hibernated parent resumes at %d MB; a different size cold-boots", cfg.MemoryMB)
		}
		if cpuSet && *cpus != cfg.CPUs {
			return fmt.Errorf("hibernated parent resumes at %d CPUs; a different count cold-boots", cfg.CPUs)
		}
		if cfg.MemoryMB > 0 {
			*mem = cfg.MemoryMB
		}
		if cfg.CPUs > 0 {
			*cpus = cfg.CPUs
		}
	}
	if err := checkResources(*mem, *cpus, *network); err != nil {
		return err
	}
	if *network == "allow" {
		if *allowHost == "" {
			return fmt.Errorf("--network allow requires --allow-host")
		}
		if err := hyperv.ValidateAllowHost(*allowHost); err != nil {
			return err
		}
	} else if *allowHost != "" {
		return fmt.Errorf("--allow-host is only used with --network allow")
	}
	vmName := *name
	if vmName == "" {
		var err error
		vmName, err = randomName()
		if err != nil {
			return err
		}
	}
	if err := hyperv.ValidateName(vmName); err != nil {
		return err
	}
	parentPath, err := resolveParent(*parent)
	if err != nil {
		return err
	}
	diff := filepath.Join(config.DataRoot(), "disks", vmName+".vhdx")
	opts := hyperv.UpOptions{
		Name:         vmName,
		Parent:       parentPath,
		Diff:         diff,
		MemoryMB:     *mem,
		CPUs:         *cpus,
		Network:      *network,
		Generation:   *gen,
		DataRoot:     config.DataRoot(),
		WaitReady:    *waitReady,
		ReadyTimeout: *readyTimeout,
		AllowHost:    *allowHost,
	}
	if sealed {
		opts.BiosGUID = cfg.BiosGUID
		opts.BiosSerial = cfg.BiosSerial
		opts.BoardSerial = cfg.BoardSerial
		opts.ChassisSerial = cfg.ChassisSerial
		opts.ChassisAsset = cfg.ChassisAsset
	}
	res, err := hyperv.Up(opts)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", res.Name, res.State)
	fmt.Printf("  id:      %s\n", res.ID)
	fmt.Printf("  disk:    %s\n", res.Disk)
	fmt.Printf("  parent:  %s\n", res.Parent)
	fmt.Printf("  network: %s\n", res.Network)
	if res.AllowHost != "" {
		fmt.Printf("  allow:   TCP 443 to %s (%s)\n", res.AllowHost, strings.Join([]string(res.AllowIPs), ", "))
		fmt.Printf("  dns:     UDP/TCP 53 to %s\n", strings.Join([]string(res.DNS), ", "))
		fmt.Printf("  guest:   %s  gateway %s\n", res.GuestIP, res.Gateway)
	}
	if *mem > 1536 {
		fmt.Printf("  memory:  %d MB at boot, idle guests can shrink toward 1536 MB\n", *mem)
	} else {
		fmt.Printf("  memory:  %d MB\n", *mem)
	}
	printTimings(res.Timings)
	if !res.ParentReadOnly {
		fmt.Println("  warning: parent VHD is not read-only. Booting it will break every clone.")
	}
	if resume {
		fmt.Printf("  resume:  hibernated desktop (%d MB, %d CPUs)\n", *mem, *cpus)
	} else if sealed {
		fmt.Println("  boot:    cold boot with the sealed firmware identity")
	} else {
		fmt.Println("  boot:    first boot installs devices. The Hyper-V logo stays up while that runs.")
		fmt.Printf("  later:   hatch hv seal %s    once the desktop is ready\n", res.Name)
	}
	if res.Heartbeat != "" && res.Heartbeat != "ok" {
		fmt.Printf("  heartbeat: %s\n", res.Heartbeat)
	}
	fmt.Printf("console: hatch hv connect %s\n", res.Name)
	fmt.Printf("destroy: hatch hv down %s\n", res.Name)
	if res.AllowError != "" {
		return fmt.Errorf("%s", res.AllowError)
	}
	if launch != nil {
		started, err := hyperv.Run(hyperv.RunOptions{
			Name:       res.Name,
			Exe:        launch.Exe,
			Arg:        launch.Arg,
			Args:       launch.Args,
			User:       launch.User,
			Password:   launch.Password,
			TimeoutSec: launch.Timeout,
		})
		if err != nil {
			return fmt.Errorf("start %s: %w. %s is still running", launch.Exe, err, res.Name)
		}
		fmt.Printf("program: %s  pid %d\n", started.Exe, started.PID)
	}
	if *connect {
		return connectVM(res.Name)
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	guest := bindGuestRunFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: hatch hv run <name> --exe <guest-path> (--arg <text> | --arg-file <path>)\n")
		fmt.Fprintf(os.Stderr, "       hatch hv run <name> --ws-url wss://host/ --ws-token TOKEN\n")
		fs.PrintDefaults()
	}
	// The name is documented before the flags. Flag parsing stops at the first
	// non-flag, so peel a leading name off and parse the rest.
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" {
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: hatch hv run <name> (--exe <guest-path> (--arg <text> | --arg-file <path>) | --ws-url wss://host/ --ws-token TOKEN)")
		}
		name = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return fmt.Errorf("usage: hatch hv run <name> (--exe <guest-path> (--arg <text> | --arg-file <path>) | --ws-url wss://host/ --ws-token TOKEN)")
	}
	if err := hyperv.ValidateName(name); err != nil {
		return err
	}
	launch, err := resolveLaunch(fs, guest, guest.timeout)
	if err != nil {
		return err
	}
	if launch == nil {
		return fmt.Errorf("--exe or --ws-url is required")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	started, err := hyperv.Run(hyperv.RunOptions{
		Name:       name,
		Exe:        launch.Exe,
		Arg:        launch.Arg,
		Args:       launch.Args,
		User:       launch.User,
		Password:   launch.Password,
		TimeoutSec: launch.Timeout,
	})
	if err != nil {
		return err
	}
	fmt.Printf("program: %s  pid %d\n", started.Exe, started.PID)
	fmt.Printf("  vm: %s\n", started.Name)
	return nil
}

type guestRunFlags struct {
	exe      string
	arg      string
	argFile  string
	wsURL    string
	wsToken  string
	wsListen string
	user     string
	password string
	timeout  int
}

func bindGuestRunFlags(fs *flag.FlagSet) *guestRunFlags {
	g := &guestRunFlags{}
	fs.StringVar(&g.exe, "exe", "", "absolute path of the program inside the guest")
	fs.StringVar(&g.arg, "arg", "", "one argument to pass; use --arg-file when it is large")
	fs.StringVar(&g.argFile, "arg-file", "", "UTF-8 file passed as one argument; a leading BOM is ignored")
	fs.StringVar(&g.wsURL, "ws-url", "", "WebSocket URL passed to wstoudp in the guest")
	fs.StringVar(&g.wsToken, "ws-token", "", "auth token passed to wstoudp in the guest")
	fs.StringVar(&g.wsListen, "ws-listen", "", "UDP address wstoudp binds (default 127.0.0.1:51820)")
	fs.StringVar(&g.user, "guest-user", "User", "guest account that runs the program")
	fs.StringVar(&g.password, "guest-password", "Rdp-test-1", "password for --guest-user")
	fs.IntVar(&g.timeout, "run-timeout", 180, "seconds to wait for the guest to accept the program")
	return g
}

func resolveLaunch(fs *flag.FlagSet, guest *guestRunFlags, timeout int) (*hyperv.GuestLaunch, error) {
	ws := flagPassed(fs, "ws-url") || flagPassed(fs, "ws-token") || flagPassed(fs, "ws-listen")
	exe := flagPassed(fs, "exe") || flagPassed(fs, "arg") || guest.argFile != ""
	if ws && exe {
		return nil, fmt.Errorf("pass either --ws-url and --ws-token, or --exe, not both")
	}
	if ws {
		return hyperv.ResolveWstoudpLaunch(guest.wsURL, guest.wsToken, guest.wsListen, guest.user, guest.password, timeout)
	}
	return hyperv.ResolveGuestLaunch(guest.exe, guest.arg, guest.argFile, guest.user, guest.password, flagPassed(fs, "arg"), timeout)
}

func flagPassed(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	all := fs.Bool("all", false, "destroy every throwaway VM created by this tool")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if *all {
		if fs.NArg() != 0 {
			return fmt.Errorf("do not pass a name with --all")
		}
		res, err := hyperv.DownAll(config.DataRoot())
		if err != nil {
			return err
		}
		if len(res.Removed) == 0 {
			fmt.Println("no throwaway VMs")
			return nil
		}
		for _, vm := range res.Removed {
			fmt.Printf("removed %s\n", vm.Name)
		}
		return nil
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: hatch hv down <name> | hatch hv down --all")
	}
	if err := hyperv.ValidateName(fs.Arg(0)); err != nil {
		return err
	}
	res, err := hyperv.Down(fs.Arg(0), config.DataRoot())
	if err != nil {
		return err
	}
	for _, vm := range res.Removed {
		fmt.Printf("removed %s\n", vm.Name)
		for _, disk := range vm.Disks {
			fmt.Printf("  disk %s\n", disk)
		}
	}
	return nil
}

func cmdList() error {
	if err := requireHyperV(); err != nil {
		return err
	}
	vms, err := hyperv.List()
	if err != nil {
		return err
	}
	if len(vms) == 0 {
		fmt.Println("no VMs")
		return nil
	}
	for _, vm := range vms {
		kind := "other"
		switch vm.Notes {
		case "hyper-v-sandbox throwaway":
			kind = "throwaway"
		case "hyper-v-sandbox parent-builder":
			kind = "parent-builder"
		}
		fmt.Printf("%-16s %-12s %-16s %4d MB  %s\n", vm.Name, vm.State, kind, vm.MemoryMB, vm.Disk)
	}
	return nil
}

func cmdConnect(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: hatch hv connect <name>")
	}
	if err := hyperv.ValidateName(args[0]); err != nil {
		return err
	}
	return connectVM(args[0])
}

func cmdBootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	iso := fs.String("iso", "", "Windows installation ISO")
	vhd := fs.String("vhd", "", "new parent VHDX path")
	name := fs.String("name", "gold", "builder VM name")
	mem := fs.Int("memory-mb", 4096, "startup memory in MB")
	cpus := fs.Int("cpus", 2, "virtual processors")
	size := fs.Int("size-gb", 64, "dynamic VHD size in GB")
	network := fs.String("network", "default", "none, private, or default")
	noConnect := fs.Bool("no-connect", false, "do not open vmconnect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if *iso == "" {
		return fmt.Errorf("usage: hatch hv bootstrap --iso C:\\path\\Windows.iso [--name gold]")
	}
	if err := hyperv.ValidateName(*name); err != nil {
		return err
	}
	if *network == "allow" {
		return fmt.Errorf("--network allow is only supported by hv up")
	}
	if err := checkResources(*mem, *cpus, *network); err != nil {
		return err
	}
	isoPath, err := filepath.Abs(*iso)
	if err != nil {
		return err
	}
	vhdPath := *vhd
	if vhdPath == "" {
		vhdPath = filepath.Join(config.DataRoot(), "parents", *name+".vhdx")
	}
	vhdPath, err = filepath.Abs(vhdPath)
	if err != nil {
		return err
	}
	res, err := hyperv.Bootstrap(*name, vhdPath, isoPath, *network, config.DataRoot(), *mem, *cpus, *size)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", res.Name, res.State)
	fmt.Printf("  vhd: %s\n", res.VHD)
	fmt.Println("Install Windows in the console. When it is the way you want clones to start, run this inside the guest:")
	fmt.Println(`  C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /mode:vm`)
	fmt.Printf("After it shuts down:\n  hatch hv retire %s\n", res.Name)
	if !*noConnect {
		return connectVM(res.Name)
	}
	return nil
}

func cmdRetire(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: hatch hv retire <builder-name>")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if err := hyperv.ValidateName(args[0]); err != nil {
		return err
	}
	res, err := hyperv.Retire(args[0])
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.ParentVHD = res.Parent
	cfg.Resume = false
	cfg.Sealed = false
	cfg.BiosGUID = ""
	cfg.BiosSerial = ""
	cfg.BoardSerial = ""
	cfg.ChassisSerial = ""
	cfg.ChassisAsset = ""
	cfg.MemoryMB = 0
	cfg.CPUs = 0
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("parent VHD: %s (read-only)\n", res.Parent)
	fmt.Println("saved as the default parent. Start a throwaway clone with:")
	fmt.Println("  hatch hv up")
	return nil
}

func cmdSeal(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: hatch hv seal <name> [parent.vhdx]")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if err := hyperv.ValidateName(args[0]); err != nil {
		return err
	}
	dest := filepath.Join(config.DataRoot(), "parents", "boot.vhdx")
	if len(args) == 2 {
		abs, err := filepath.Abs(args[1])
		if err != nil {
			return err
		}
		dest = abs
	}
	res, err := hyperv.Seal(args[0], dest, config.DataRoot())
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.ParentVHD = res.Parent
	cfg.MemoryMB = res.MemoryMB
	cfg.CPUs = res.CPUs
	cfg.Resume = false
	cfg.Sealed = true
	cfg.BiosGUID = res.BiosGUID
	cfg.BiosSerial = res.BiosSerial
	cfg.BoardSerial = res.BoardSerial
	cfg.ChassisSerial = res.ChassisSerial
	cfg.ChassisAsset = res.ChassisAsset
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("sealed parent: %s\n", res.Parent)
	fmt.Printf("firmware:      %s\n", res.BiosGUID)
	fmt.Println("later clones cold-boot as this machine:")
	fmt.Println("  hatch hv up --connect --wait-ready")
	return nil
}

func cmdSave(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: hatch hv save <name>")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if err := hyperv.ValidateName(args[0]); err != nil {
		return err
	}
	res, err := hyperv.Save(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s  checkpoint %s  %s\n", res.Name, res.Checkpoint, res.State)
	fmt.Println("the desktop is stored. Discard later changes with:")
	fmt.Printf("  hatch hv reset %s\n", res.Name)
	return nil
}

func cmdReset(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: hatch hv reset <name>")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if err := hyperv.ValidateName(args[0]); err != nil {
		return err
	}
	res, err := hyperv.Reset(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", res.Name, res.State)
	if res.Resumed {
		fmt.Println("restored the saved desktop")
	} else {
		fmt.Println("checkpoint had no saved memory, so Windows is booting")
	}
	fmt.Printf("console: hatch hv connect %s\n", res.Name)
	return nil
}

func cmdAdopt(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: hatch hv adopt <name>")
	}
	if err := requireHyperV(); err != nil {
		return err
	}
	if err := hyperv.ValidateName(args[0]); err != nil {
		return err
	}
	dest := filepath.Join(config.DataRoot(), "parents", "resume.vhdx")
	res, err := hyperv.Adopt(args[0], dest, config.DataRoot())
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.ParentVHD = res.Parent
	cfg.MemoryMB = res.MemoryMB
	cfg.CPUs = res.CPUs
	cfg.Resume = true
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("resume parent: %s (read-only)\n", res.Parent)
	fmt.Printf("locked to %d MB and %d CPUs\n", res.MemoryMB, res.CPUs)
	fmt.Println("later clones restore that desktop:")
	fmt.Println("  hatch hv up --connect")
	return nil
}

func cmdParent(args []string) error {
	if len(args) == 0 {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.ParentVHD == "" {
			fmt.Println("(not set)")
			return nil
		}
		fmt.Println(cfg.ParentVHD)
		return nil
	}
	if len(args) == 2 && args[0] == "set" {
		abs, err := filepath.Abs(args[1])
		if err != nil {
			return err
		}
		if _, err := os.Stat(abs); err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if !strings.EqualFold(cfg.ParentVHD, abs) {
			cfg.Resume = false
			cfg.Sealed = false
			cfg.BiosGUID = ""
			cfg.BiosSerial = ""
			cfg.BoardSerial = ""
			cfg.ChassisSerial = ""
			cfg.ChassisAsset = ""
			cfg.MemoryMB = 0
			cfg.CPUs = 0
		}
		cfg.ParentVHD = abs
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Printf("parent VHD: %s\n", abs)
		return nil
	}
	return fmt.Errorf("usage: hatch hv parent | hatch hv parent set <vhdx>")
}

func resolveParent(flagValue string) (string, error) {
	path := flagValue
	if path == "" {
		cfg, err := config.Load()
		if err != nil {
			return "", err
		}
		path = cfg.ParentVHD
	}
	if path == "" {
		return "", fmt.Errorf("no parent VHD. Build one with `hatch hv bootstrap --iso <Windows.iso>`, sysprep /mode:vm, then `hatch hv retire gold`")
	}
	abs, err := filepath.Abs(path)
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
	return fmt.Errorf("Hyper-V management needs membership in Hyper-V Administrators, or an elevated terminal.\nThis logon token has neither. Sign out and back in after joining the group, or right-click Windows Terminal, choose Run as administrator, then rerun this command")
}

func checkResources(mem, cpus int, network string) error {
	if mem < 1024 || mem > 65536 {
		return fmt.Errorf("memory-mb must be between 1024 and 65536")
	}
	if cpus < 1 || cpus > 32 {
		return fmt.Errorf("cpus must be between 1 and 32")
	}
	switch network {
	case "none", "private", "default", "allow":
		return nil
	default:
		return fmt.Errorf("network must be none, private, default, or allow")
	}
}

func randomName() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sbx-" + hex.EncodeToString(b[:]), nil
}

func printTimings(t map[string]int) {
	order := []struct {
		key, label string
	}{
		{"differencing_disk_ms", "differencing disk"},
		{"create_vm_ms", "create VM"},
		{"start_vm_ms", "start VM"},
		{"heartbeat_ms", "guest heartbeat"},
		{"guest_net_ms", "guest address"},
	}
	for _, item := range order {
		if ms, ok := t[item.key]; ok {
			fmt.Printf("  %-20s %dms\n", item.label, ms)
		}
	}
}

func connectVM(name string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "vmconnect.exe")
	cmd := exec.Command(exe, "localhost", name)
	null, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer null.Close()
	cmd.Stdin = null
	cmd.Stdout = null
	cmd.Stderr = null
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("vmconnect: %w", err)
	}
	fmt.Printf("console window opened for %s\n", name)
	return nil
}
