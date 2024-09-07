package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func checkAdminRights() bool {
	if runtime.GOOS == "windows" {
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	}
	return os.Geteuid() == 0
}

func main() {
	if checkAdminRights() {
		fmt.Println("Warning: This program is running with elevated privileges.")
		fmt.Println("It is recommended to run it as a regular user and use elevated privileges only when prompted.")
		fmt.Println("Continue? (yes/no)")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "yes" {
			fmt.Println("Exiting.")
			os.Exit(1)
		}
	}

	// Register the sub-commands under root
	rootCmd := newRootCommand()
	rootCmd.AddCommand(
		newNVCommand(),
		newKeyCommand(),
		newx509Command(),
		newSSHCommand(),
		newOpenPGPCommand(),
	)
	rootCmd.SetOutput(os.Stderr)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tpmk",
		Short: "TPM2 key and storage management toolkit",
	}
	return cmd
}
