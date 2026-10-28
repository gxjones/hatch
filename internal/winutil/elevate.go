package winutil

import (
	"syscall"
	"unsafe"
)

var procCheckTokenMembership = syscall.NewLazyDLL("advapi32.dll").NewProc("CheckTokenMembership")

type tokenElevation struct {
	TokenIsElevated uint32
}

// Hyper-V Administrators. UAC does not filter this group, so a normal
// logon token that contains it can manage Hyper-V.
const hyperVAdministratorsSID = "S-1-5-32-578"

// IsElevated reports whether this process holds an elevated admin token.
// A normal terminal on this machine is a filtered admin token, and Hyper-V
// rejects that even when the user is in Administrators.
func IsElevated() bool {
	token, err := openCurrentToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return tokenElevated(token)
}

// InHyperVAdministrators reports whether the process token includes the
// Hyper-V Administrators group. The group is recorded at logon, so a user
// added while already signed in must sign out and back in before this is true.
func InHyperVAdministrators() bool {
	return tokenHasSID(hyperVAdministratorsSID)
}

func tokenHasSID(sid string) bool {
	parsed, err := syscall.StringToSid(sid)
	if err != nil {
		return false
	}
	// A null token uses this thread's token. CheckTokenMembership rejects a
	// primary token handle, and a null handle makes it duplicate one.
	var member int32
	r, _, _ := procCheckTokenMembership.Call(
		0,
		uintptr(unsafe.Pointer(parsed)),
		uintptr(unsafe.Pointer(&member)),
	)
	return r != 0 && member != 0
}

func openCurrentToken() (syscall.Token, error) {
	// Current-process pseudo-handle is (HANDLE)-1. Using it avoids the
	// GetCurrentProcess signature, which has changed across Go releases.
	proc := syscall.Handle(^uintptr(0))
	var token syscall.Token
	err := syscall.OpenProcessToken(proc, syscall.TOKEN_QUERY, &token)
	return token, err
}

func tokenElevated(token syscall.Token) bool {
	var elev tokenElevation
	var out uint32
	err := syscall.GetTokenInformation(
		token,
		syscall.TokenElevation,
		(*byte)(unsafe.Pointer(&elev)),
		uint32(unsafe.Sizeof(elev)),
		&out,
	)
	if err != nil {
		return false
	}
	return elev.TokenIsElevated != 0
}
