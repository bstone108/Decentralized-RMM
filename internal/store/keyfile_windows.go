//go:build windows

package store

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// restrictKeyFile leaves the key readable by the current user only. The DACL
// is protected so it does not inherit a broader ACE from the parent directory.
func restrictKeyFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("windows token user: %w", err)
	}
	sid := user.User.Sid
	var pinner runtime.Pinner
	pinner.Pin(user)
	defer pinner.Unpin()

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build key file ACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		sid,
		nil,
		acl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("restrict key file ACL: %w", err)
	}
	return nil
}
