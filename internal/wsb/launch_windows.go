package wsb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const featureHint = "Windows Sandbox is not installed. From an elevated PowerShell:\n  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM\nThen reboot."

const alreadyRunning = "Only one running instance of Windows Sandbox is allowed. Close the existing Windows Sandbox window and try again."

// Launch starts Windows Sandbox with a .wsb configuration.
// Windows allows one sandbox VM per user. A second launch opens an error
// window and leaves the existing VM as it is.
// When wait is false, Launch returns once the process is still alive after a short grace period.
func Launch(wsbPath string, wait bool) error {
	if err := CheckRunning(); err != nil {
		return err
	}
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsSandbox.exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("%s", featureHint)
	}
	cmd := exec.Command(exe, wsbPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if wait {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("Windows Sandbox exited: %w", err)
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("Windows Sandbox exited: %w", err)
		}
		return nil
	case <-time.After(3 * time.Second):
		return nil
	}
}

// CheckRunning reports the one-instance limit before we open another client window.
func CheckRunning() error {
	running, err := sandboxInstanceRunning()
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("%s", alreadyRunning)
	}
	return nil
}

func sandboxInstanceRunning() (bool, error) {
	const snapProcess = 0x00000002
	snap, err := syscall.CreateToolhelp32Snapshot(snapProcess, 0)
	if err != nil {
		return false, fmt.Errorf("list processes: %w", err)
	}
	defer syscall.CloseHandle(snap)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := syscall.Process32First(snap, &entry); err != nil {
		return false, fmt.Errorf("list processes: %w", err)
	}
	for {
		name := strings.ToLower(syscall.UTF16ToString(entry.ExeFile[:]))
		switch name {
		case "vmmemwindowssandbox.exe", "windowssandboxremotesession.exe":
			return true, nil
		}
		if err := syscall.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return false, nil
}
