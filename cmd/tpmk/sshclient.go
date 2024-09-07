package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"
)

type sshClientOptions struct {
	device         string
	keyPassword    string
	crtPassword    string
	crtFormat      string
	crtFile        string
	crtHandle      string
	knownHostsFile string
	insecure       bool
	proxySocks5    string
	interactive    bool
}

func newSSHClientCommand() *cobra.Command {
	var opt sshClientOptions

	cmd := &cobra.Command{
		Use:   "client <handle> <user@host:port> [command]",
		Short: "Execute a command remotely or start an interactive session",
		Long: `Executes a command on an SSH server using a key in the TPM
or starts an interactive session. Supports host and client certificates,
with the client certificate optionally read from an NV index in the TPM.

Unless -k is used, a known hosts file in OpenSSH format needs
to be provided with --known-hosts/-s. If none is given in the
command line, $HOME/.ssh/known_hosts will be used if available
followed by /etc/ssh/ssh_known_hosts.

Note that no assumptions are made regarding user or port. Both
need to be specified in the command in the typical format:
<user>@<host>:<port>
`,
		Example: `  tpmk ssh client 0x81000000 root@host:22 "ls -l"
  tpmk ssh client -i 0x1500000 0x81000000 root@host:22`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHClient(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.keyPassword, "key-password", "p", "", "TPM key password")
	flags.StringVarP(&opt.knownHostsFile, "known-hosts", "s", "", "Acceptable host keys or certs")
	flags.StringVarP(&opt.crtFile, "crt-file", "c", "", "Client certificate file")
	flags.StringVarP(&opt.crtHandle, "crt-handle", "i", "", "Read the client cert from a TPM NV index")
	flags.StringVarP(&opt.crtPassword, "crt-password", "n", "", "TPM NV index password")
	flags.StringVarP(&opt.crtFormat, "crt-format", "f", "openssh", "Format of the client cert")
	flags.BoolVarP(&opt.insecure, "insecure", "k", false, "Accept any host key")
	flags.StringVarP(&opt.proxySocks5, "socks5-proxy", "P", "", "Socks5 proxy string")
	flags.BoolVarP(&opt.interactive, "interactive", "t", false, "Start an interactive session")
	return cmd
}

func runSSHClient(opt sshClientOptions, args []string) error {
	keyHandle, err := parseHandle(args[0])
	if err != nil {
		return err
	}
	remote := args[1]
	var command string
	if len(args) > 2 {
		command = args[2]
	}

	// Confirm that the provided arguments make sense
	if opt.insecure && opt.knownHostsFile != "" {
		return errors.New("can't use -k with -s")
	}
	if opt.crtFile != "" && opt.crtHandle != "" {
		return errors.New("can use either -c or -i, not both")
	}

	// Check TPM device access for UNIX
	if runtime.GOOS == "linux" && !canAccessTPM(opt.device) {
		return handleTPMAccess()
	}

	// Parse the remote location into user and host
	s := strings.Split(remote, "@")
	if len(s) != 2 {
		return errors.New("require user@host:port for remote endpoint")
	}
	user := s[0]
	host := s[1]

	// Open the TPM
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return errors.Wrap(err, "opening "+opt.device)
	}
	defer dev.Close()

	// Use the key in the TPM to build an ssh.Signer
	pk, err := tpmk.NewRSAPrivateKey(dev, keyHandle, opt.keyPassword)
	if err != nil {
		return errors.Wrap(err, "accessing key")
	}
	signer, err := ssh.NewSignerFromSigner(pk)
	if err != nil {
		return errors.Wrap(err, "invalid key")
	}

	// Use client certificate, if provided to extend the ssh.Signer with a cerfificate
	if opt.crtFile != "" || opt.crtHandle != "" {
		var b []byte
		var err error
		if opt.crtHandle != "" { // Read the cert from NV
			crtHandle, err := parseHandle(opt.crtHandle)
			if err != nil {
				return err
			}
			b, err = tpmk.NVRead(dev, crtHandle, "")
			if err != nil {
				return errors.Wrap(err, "reading crt from TPM")
			}
		} else { // Read the cert from file
			b, err = ioutil.ReadFile(opt.crtFile)
			if err != nil {
				return errors.Wrap(err, "reading client crt file")
			}
		}

		// Unmarshall the certificate according to the provided format
		var pub ssh.PublicKey
		switch opt.crtFormat {
		case "openssh":
			pub, err = tpmk.ParseOpenSSHPublicKey(b)
		case "wire":
			pub, err = ssh.ParsePublicKey(b)
		default:
			return fmt.Errorf("unsupported certificate format '%s", opt.crtFormat)
		}
		if err != nil {
			return errors.Wrap(err, "parsing client crt file")
		}

		// Make sure the provided cert really was one
		crt, ok := pub.(*ssh.Certificate)
		if !ok {
			return errors.New("client cert file not of the right type")
		}

		// Extend the signer used in the handshake to present the cert to the server
		signer, err = ssh.NewCertSigner(crt, signer)
		if err != nil {
			return err
		}
	}

	// Find a known_hosts file with valid host keys or certificates. Use the following search order:
	// 1. Provided by command line options
	// 2. Disabled via command line (-k)
	// 3. $HOME/.ssh/known_hosts (Unix) or %USERPROFILE%\.ssh\known_hosts (Windows) if the environment variable is non-empty
	// 4. If no known_hosts file is found, return an error
	var hostKeyCallback ssh.HostKeyCallback
	switch {
	case opt.knownHostsFile != "": // Parse and use the given known_hosts file
		hostKeyCallback, err = knownhosts.New(opt.knownHostsFile)
		if err != nil {
			return errors.Wrap(err, "reading host key file")
		}
	case opt.insecure: // Don't validate and accept anything presented by the host
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	default: // Try to find a known hosts file in the user's home directory
		var knownHostsFile string
		if runtime.GOOS == "windows" {
			userProfile := os.Getenv("USERPROFILE")
			if userProfile != "" {
				knownHostsFile = filepath.Join(userProfile, ".ssh", "known_hosts")
			}
		} else {
			home := os.Getenv("HOME")
			if home != "" {
				knownHostsFile = filepath.Join(home, ".ssh", "known_hosts")
			}
		}

		if knownHostsFile != "" {
			hostKeyCallback, err = knownhosts.New(knownHostsFile)
			if err == nil {
				break
			}
			if !os.IsNotExist(err) {
				return errors.Wrap(err, "reading known_hosts file: "+knownHostsFile)
			}
		}

		// If we reach here, we couldn't find a valid known_hosts file
		return errors.New("unable to find a known_hosts file")
	}

	// Build SSH client config with just public key auth
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	var client *ssh.Client
	if opt.proxySocks5 != "" {
		socksConnection, err := proxy.SOCKS5("tcp", opt.proxySocks5, nil, proxy.Direct)
		if err != nil {
			return errors.Wrap(err, "could not create socks5 proxy "+opt.proxySocks5)
		}
		conn, err := socksConnection.Dial("tcp", host)
		if err != nil {
			return errors.Wrap(err, "could not create connection with socks.")
		}
		defer conn.Close()
		clientConnection, chans, reqs, err := ssh.NewClientConn(conn, host, config)
		if err != nil {
			return errors.Wrap(err, "could not create socks5 proxy client "+opt.proxySocks5)
		}
		client = ssh.NewClient(clientConnection, chans, reqs)
		defer client.Close()
	} else {
		client, err = ssh.Dial("tcp", host, config)
		if err != nil {
			return errors.Wrap(err, "connecting to "+host)
		}
		defer client.Close()
	}

	session, err := client.NewSession()
	if err != nil {
		return errors.Wrap(err, "creating SSH session")
	}
	defer session.Close()

	if opt.interactive {
		// Request pseudo terminal
		if err := session.RequestPty("xterm", 40, 80, ssh.TerminalModes{}); err != nil {
			return errors.Wrap(err, "requesting pseudo terminal")
		}

		// Set up stdin/stdout/stderr
		session.Stdin = os.Stdin
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr

		// Start interactive shell
		if err := session.Shell(); err != nil {
			return errors.Wrap(err, "starting shell")
		}

		// Wait for session to finish
		return session.Wait()
	} else if command != "" {
		// Run a single command
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		return session.Run(command)
	} else {
		return errors.New("either a command or the interactive flag must be provided")
	}
}

func canAccessTPM(device string) bool {
	_, err := os.OpenFile(device, os.O_RDWR, 0)
	return err == nil
}

func handleTPMAccess() error {
	fmt.Println("You don't have sufficient permissions to access the TPM device.")
	fmt.Println("Choose an option to resolve this issue:")
	fmt.Println("1. Add current user to the 'tss' group (recommended, requires sudo)")
	fmt.Println("2. Run tpmk with sudo (not recommended)")
	fmt.Println("3. Exit")

	var choice int
	fmt.Print("Enter your choice (1-3): ")
	fmt.Scanln(&choice)

	switch choice {
	case 1:
		return addUserToTssGroup()
	case 2:
		fmt.Println("Please run the command again with sudo.")
		os.Exit(0)
	case 3:
		fmt.Println("Exiting.")
		os.Exit(0)
	default:
		return errors.New("invalid choice")
	}
	return nil
}

func addUserToTssGroup() error {
	currentUser, err := user.Current()
	if err != nil {
		return errors.Wrap(err, "getting current user")
	}

	// Check if the tss group exists
	_, err = exec.Command("getent", "group", "tss").Output()
	if err != nil {
		// tss group doesn't exist, offer to create it
		fmt.Println("The 'tss' group does not exist. Would you like to create it?")
		fmt.Print("Enter 'yes' to create the group or any other key to exit: ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "yes" {
			fmt.Println("Exiting without making changes.")
			os.Exit(0)
		}

		// Create tss group
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
	fmt.Println("Please log out and log back in for the changes to take effect.")
	fmt.Println("After logging back in, run the tpmk command again.")
	os.Exit(0)
	return nil
}
