package hyperv

import (
	"fmt"
	"regexp"
)

// VM names are embedded in paths and passed to Hyper-V. Keep them boring.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid VM name %q (use letters, digits, '.', '_' or '-', max 64 chars)", name)
	}
	return nil
}
