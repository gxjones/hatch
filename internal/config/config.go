package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type File struct {
	ParentVHD string `json:"parentVhd,omitempty"`
	MemoryMB  int    `json:"memoryMB,omitempty"`
	CPUs      int    `json:"cpus,omitempty"`
	// Resume means ParentVHD was hibernated. Clones must use MemoryMB and CPUs
	// or Windows discards the saved session and cold-boots.
	Resume bool `json:"resume,omitempty"`
	// Sealed means ParentVHD has already finished its first-boot device setup.
	// Clones copy this firmware identity so Windows treats them as that machine.
	Sealed        bool   `json:"sealed,omitempty"`
	BiosGUID      string `json:"biosGuid,omitempty"`
	BiosSerial    string `json:"biosSerial,omitempty"`
	BoardSerial   string `json:"boardSerial,omitempty"`
	ChassisSerial string `json:"chassisSerial,omitempty"`
	ChassisAsset  string `json:"chassisAsset,omitempty"`
}

func Dir() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "hyper-v-sandbox")
}

func Path() string {
	return filepath.Join(Dir(), "config.json")
}

// DataRoot holds differencing disks. It lives in ProgramData so the Hyper-V
// service (SYSTEM) can read them. A user-profile path often fails that check.
func DataRoot() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "hyper-v-sandbox")
}

func Load() (File, error) {
	b, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return File{}, nil
		}
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, err
	}
	return f, nil
}

func Save(f File) error {
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(Path(), b, 0o644)
}
