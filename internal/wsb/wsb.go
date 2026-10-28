package wsb

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Options struct {
	MemoryMB     int
	Networking   bool
	GPU          bool
	AudioInput   bool
	VideoInput   bool
	Protected    bool
	Printers     bool
	Clipboard    bool
	HostFolder   string
	GuestFolder  string
	MapReadOnly  bool
	LogonCommand string
}

type configuration struct {
	XMLName              xml.Name       `xml:"Configuration"`
	VGpu                 string         `xml:"VGpu"`
	Networking           string         `xml:"Networking"`
	AudioInput           string         `xml:"AudioInput"`
	VideoInput           string         `xml:"VideoInput"`
	ProtectedClient      string         `xml:"ProtectedClient"`
	PrinterRedirection   string         `xml:"PrinterRedirection"`
	ClipboardRedirection string         `xml:"ClipboardRedirection"`
	MemoryInMB           int            `xml:"MemoryInMB,omitempty"`
	MappedFolders        *mappedFolders `xml:"MappedFolders,omitempty"`
	LogonCommand         *logonCommand  `xml:"LogonCommand,omitempty"`
}

type mappedFolders struct {
	MappedFolder mappedFolder `xml:"MappedFolder"`
}

type mappedFolder struct {
	HostFolder    string `xml:"HostFolder"`
	SandboxFolder string `xml:"SandboxFolder,omitempty"`
	ReadOnly      bool   `xml:"ReadOnly"`
}

type logonCommand struct {
	Command string `xml:"Command"`
}

func enable(on bool) string {
	if on {
		return "Enable"
	}
	return "Disable"
}

// Build renders a Windows Sandbox configuration file.
// Schema: https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file
func Build(opts Options) ([]byte, error) {
	if opts.MemoryMB < 0 {
		return nil, fmt.Errorf("memory must be >= 0")
	}
	cfg := configuration{
		VGpu:                 enable(opts.GPU),
		Networking:           enable(opts.Networking),
		AudioInput:           enable(opts.AudioInput),
		VideoInput:           enable(opts.VideoInput),
		ProtectedClient:      enable(opts.Protected),
		PrinterRedirection:   enable(opts.Printers),
		ClipboardRedirection: enable(opts.Clipboard),
		MemoryInMB:           opts.MemoryMB,
	}
	if opts.HostFolder != "" {
		cfg.MappedFolders = &mappedFolders{MappedFolder: mappedFolder{
			HostFolder:    opts.HostFolder,
			SandboxFolder: opts.GuestFolder,
			ReadOnly:      opts.MapReadOnly,
		}}
	}
	if opts.LogonCommand != "" {
		cfg.LogonCommand = &logonCommand{Command: opts.LogonCommand}
	}
	body, err := xml.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+len(xml.Header)+3)
	out = append(out, 0xEF, 0xBB, 0xBF) // BOM so Notepad and Sandbox agree on UTF-8
	out = append(out, []byte(xml.Header)...)
	out = append(out, body...)
	out = append(out, '\n')
	return out, nil
}

// Write stores the configuration where the Sandbox process can read it after we return.
func Write(dir string, opts Options) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, err := Build(opts)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("hatch-%s.wsb", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
