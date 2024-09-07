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

	if !canAccessTPM(device) {
		if err := handleTPMAccess(); err != nil {
			return nil, err
		}
	}
	return tpm2.OpenTPM(device)
}

// detectTPMDevice attempts to find the TPM device on the system
func detectTPMDevice() (string, error) {
	// Search in /sys/class/tpm
	tpmDirs, err := ioutil.ReadDir("/sys/class/tpm")
	if err != nil {
		return "", errors.Wrap(err, "reading /sys/class/tpm directory")
	}

	for _, dir := range tpmDirs {
		if strings.HasPrefix(dir.Name(), "tpm") {
			// Check if a corresponding device exists in /dev
			devicePath := filepath.Join("/dev", dir.Name())
			if _, err := os.Stat(devicePath); err == nil {
				return devicePath, nil
			}

			// Also check for a possible "raw" device
			rawDevicePath := filepath.Join("/dev", dir.Name()+"rm")
			if _, err := os.Stat(rawDevicePath); err == nil {
				return rawDevicePath, nil
			}
		}
	}

	// Fallback: Search directly in /dev for tpm devices
	devEntries, err := ioutil.ReadDir("/dev")
	if err != nil {
		return "", errors.Wrap(err, "reading /dev directory")
	}

	for _, entry := range devEntries {
		if strings.HasPrefix(entry.Name(), "tpm") {
			return filepath.Join("/dev", entry.Name()), nil
		}
	}

	return "", errors.New("no TPM device found")
}

// canAccessTPM checks if the current user can access the TPM device
func canAccessTPM(device string) bool {
	_, err := os.OpenFile(device, os.O_RDWR, 0)
	return err == nil
}

// handleTPMAccess manages the process of setting up TPM access for the user
func handleTPMAccess() error {
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

	return setupTPMAccess()
}

// setupTPMAccess configures the system to allow TPM access for the current user
func setupTPMAccess() error {
	device, err := detectTPMDevice()
	if err != nil {
		return errors.Wrap(err, "detecting TPM device")
	}

	// Extract the base name of the device
	deviceName := filepath.Base(device)

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
	rule := []byte(fmt.Sprintf(`KERNEL=="%s", GROUP="tss"`, deviceName))
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
	fmt.Println("UDEV rules created")

	fmt.Println("TPM access has been set up.")
	fmt.Println("Please reboot your system for all changes to take effect.")
	fmt.Println("After rebooting, run the tpmk command again.")
	os.Exit(0)
	return nil
}
