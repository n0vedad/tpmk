//go:build !windows
// +build !windows

package tpmk

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/pkg/errors"
)

// openImpl opens the TPM identified by the device name
func openImpl(device string) (io.ReadWriteCloser, error) {
	if runtime.GOOS == "linux" && !canAccessTPM(device) {
		if err := handleTPMAccess(device); err != nil {
			return nil, err
		}
	}
	return tpm2.OpenTPM(device)
}

func canAccessTPM(device string) bool {
	_, err := os.OpenFile(device, os.O_RDWR, 0)
	return err == nil
}

func handleTPMAccess(device string) error {
	fmt.Println("You don't have sufficient permissions to access the TPM device.")
	fmt.Println("Would you like to set up TPM access for your user? This requires sudo privileges.")
	fmt.Print("Enter 'yes' to proceed or any other key to exit: ")

	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) != "yes" {
		fmt.Println("Exiting without making changes.")
		os.Exit(0)
	}

	return setupTPMAccess(device)
}

func setupTPMAccess(device string) error {
	currentUser, err := user.Current()
	if err != nil {
		return errors.Wrap(err, "getting current user")
	}

	// Check if the tss group exists
	_, err = exec.Command("getent", "group", "tss").Output()
	if err != nil {
		fmt.Println("The 'tss' group does not exist. Creating it now...")
		cmd := exec.Command("sudo", "groupadd", "tss")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return errors.Wrap(err, "creating tss group")
		}
		fmt.Println("The 'tss' group has been created.")
	}

	// Add user to tss group
	cmd := exec.Command("sudo", "usermod", "-a", "-G", "tss", currentUser.Username)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "adding user to tss group")
	}
	fmt.Println("User has been added to the 'tss' group.")

	// Set up udev rules
	rule := []byte(fmt.Sprintf(`KERNEL=="%s", GROUP="tss"`, device))
	if err := ioutil.WriteFile("/tmp/60-tpm.rules", rule, 0644); err != nil {
		return errors.Wrap(err, "creating temporary udev rule file")
	}

	cmd = exec.Command("sudo", "mv", "/tmp/60-tpm.rules", "/etc/udev/rules.d/60-tpm.rules")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "moving udev rule file")
	}

	cmd = exec.Command("sudo", "udevadm", "control", "--reload-rules")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "reloading udev rules")
	}

	cmd = exec.Command("sudo", "udevadm", "trigger")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "triggering udev rules")
	}

	fmt.Println("TPM access has been set up.")
	fmt.Println("Please reboot your system for all changes to take effect.")
	fmt.Println("After rebooting, run the tpmk command again.")
	os.Exit(0)
	return nil
}
