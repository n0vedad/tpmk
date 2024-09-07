//go:build linux
// +build linux

package tpmk

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/pkg/errors"
)

// openImpl opens the TPM identified by the device name
func openImpl() (io.ReadWriteCloser, error) {
	device, err := detectTPMDevice()
	if err != nil {
		return nil, errors.Wrap(err, "detecting TPM device")
	}

	// Initial check for TPM access
	if !canAccessTPM(device) {
		fmt.Printf("Cannot access TPM device %s. Attempting to set up access...\n", device)
		if err := setupTPMAccess(device); err != nil {
			return nil, errors.Wrap(err, "setting up TPM access")
		}
	}

	return tpm2.OpenTPM(device)
}

// canAccessTPM checks if the current user can access the TPM device
func canAccessTPM(device string) bool {
	_, err := os.OpenFile(device, os.O_RDWR, 0)
	return err == nil
}

// detectTPMDevice attempts to find the TPM device on the system
func detectTPMDevice() (string, error) {
	// Prioritize /dev/tpmrm0
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return "/dev/tpmrm0", nil
	}

	// Search for TPM devices in /sys/class/tpm
	tpmDirs, err := ioutil.ReadDir("/sys/class/tpm")
	if err != nil {
		return "", errors.Wrap(err, "reading /sys/class/tpm directory")
	}

	for _, dir := range tpmDirs {
		if strings.HasPrefix(dir.Name(), "tpm") {
			// Check for TPM Resource Manager (TRM) device first
			trmDevice := filepath.Join("/dev", dir.Name()+"rm")
			if _, err := os.Stat(trmDevice); err == nil {
				return trmDevice, nil
			}

			// Fallback: Check for direct TPM device
			directDevice := filepath.Join("/dev", dir.Name())
			if _, err := os.Stat(directDevice); err == nil {
				return directDevice, nil
			}
		}
	}

	return "", errors.New("no TPM device found")
}

// setupTPMAccess configures the system to allow TPM access for the current user
func setupTPMAccess(device string) error {
	fmt.Println("You don't have sufficient permissions to access the TPM device.")
	fmt.Println("Would you like to set up TPM access for your user?")
	fmt.Println("This requires sudo privileges for adding your user to a special group and setting up UDEV rules.")
	fmt.Print("Enter 'yes' to proceed or any other key to exit: ")

	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) != "yes" {
		fmt.Println("Exiting without making changes.")
		os.Exit(0)
	}

	deviceName := filepath.Base(device)
	rule := fmt.Sprintf(`KERNEL=="%s", GROUP="tss"`, deviceName)

	// Check if tss group exists
	_, err := exec.Command("getent", "group", "tss").Output()
	if err != nil {
		fmt.Println("The 'tss' group does not exist. Creating it now...")
		cmd := exec.Command("sudo", "groupadd", "tss")
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, "creating tss group")
		}
	}

	// Check if current user is already in tss group
	currentUser, err := user.Current()
	if err != nil {
		return errors.Wrap(err, "getting current user")
	}
	groups, err := exec.Command("groups", currentUser.Username).Output()
	if err != nil {
		return errors.Wrap(err, "getting user groups")
	}
	if !strings.Contains(string(groups), "tss") {
		fmt.Println("Adding current user to 'tss' group...")
		cmd := exec.Command("sudo", "usermod", "-a", "-G", "tss", currentUser.Username)
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, "adding user to tss group")
		}
	} else {
		fmt.Println("User is already a member of the 'tss' group.")
	}

	// Check if udev rule already exists and is correct
	existingRule, err := ioutil.ReadFile("/etc/udev/rules.d/60-tpm.rules")
	if err == nil && string(existingRule) == rule {
		fmt.Println("Correct udev rule already exists.")
	} else {
		fmt.Println("Creating UDEV rule...")
		if err := ioutil.WriteFile("/tmp/60-tpm.rules", []byte(rule), 0644); err != nil {
			return errors.Wrap(err, "creating temporary udev rules file")
		}
		cmd := exec.Command("sudo", "mv", "/tmp/60-tpm.rules", "/etc/udev/rules.d/60-tpm.rules")
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, "moving udev rule file")
		}

		cmd = exec.Command("sudo", "udevadm", "control", "--reload-rules")
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, "reloading udev rules")
		}

		cmd = exec.Command("sudo", "udevadm", "trigger")
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, "triggering udev rules")
		}
	}

	fmt.Println("TPM access has been set up.")
	fmt.Println("Please log out and log back in for the changes to take effect.")
	fmt.Println("After logging back in, run the tpmk command again.")
	os.Exit(0)
	return nil
}
