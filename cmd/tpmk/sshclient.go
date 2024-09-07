package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpmutil"
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

// main function that orchestrates the SSH client connection process
func runSSHClient(opt sshClientOptions, args []string) error {
	keyHandle, user, host, command, err := parseArguments(args)
	if err != nil {
		return err
	}

	if err := validateArguments(opt); err != nil {
		return err
	}

	signer, dev, err := setupTPMAndSigner(opt, keyHandle)
	if err != nil {
		return err
	}
	defer dev.Close()

	if opt.crtFile != "" || opt.crtHandle != "" {
		signer, err = setupClientCertificate(opt, dev, signer)
		if err != nil {
			return err
		}
	}

	hostKeyCallback, err := setupHostKeyCallback(opt)
	if err != nil {
		return err
	}

	client, err := createSSHClient(opt, user, host, signer, hostKeyCallback)
	if err != nil {
		return err
	}
	defer client.Close()

	return executeSSHSession(client, opt, command)
}

// processes the command line arguments
func parseArguments(args []string) (tpmutil.Handle, string, string, string, error) {
	keyHandle, err := parseHandle(args[0])
	if err != nil {
		return 0, "", "", "", err
	}

	remote := args[1]
	s := strings.Split(remote, "@")
	if len(s) != 2 {
		return 0, "", "", "", errors.New("require user@host:port for remote endpoint")
	}
	user := s[0]
	host := s[1]

	var command string
	if len(args) > 2 {
		command = args[2]
	}

	return keyHandle, user, host, command, nil
}

// checks for valid combinations of command line options
func validateArguments(opt sshClientOptions) error {
	if opt.insecure && opt.knownHostsFile != "" {
		return errors.New("can't use -k with -s")
	}
	if opt.crtFile != "" && opt.crtHandle != "" {
		return errors.New("can use either -c or -i, not both")
	}
	return nil
}

// opens the TPM and creates an SSH signer
func setupTPMAndSigner(opt sshClientOptions, keyHandle tpmutil.Handle) (ssh.Signer, io.ReadWriteCloser, error) {
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return nil, nil, errors.Wrap(err, "opening "+opt.device)
	}

	pk, err := tpmk.NewRSAPrivateKey(dev, keyHandle, opt.keyPassword)
	if err != nil {
		return nil, nil, errors.Wrap(err, "accessing key")
	}

	signer, err := ssh.NewSignerFromSigner(pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "invalid key")
	}

	return signer, dev, nil
}

// configures the client certificate if provided
func setupClientCertificate(opt sshClientOptions, dev io.ReadWriteCloser, signer ssh.Signer) (ssh.Signer, error) {
	var b []byte
	var err error

	if opt.crtHandle != "" {
		crtHandle, err := parseHandle(opt.crtHandle)
		if err != nil {
			return nil, err
		}
		b, err = tpmk.NVRead(dev, crtHandle, "")
		if err != nil {
			return nil, errors.Wrap(err, "reading crt from TPM")
		}
	} else {
		b, err = ioutil.ReadFile(opt.crtFile)
		if err != nil {
			return nil, errors.Wrap(err, "reading client crt file")
		}
	}

	var pub ssh.PublicKey
	switch opt.crtFormat {
	case "openssh":
		pub, err = tpmk.ParseOpenSSHPublicKey(b)
	case "wire":
		pub, err = ssh.ParsePublicKey(b)
	default:
		return nil, fmt.Errorf("unsupported certificate format '%s", opt.crtFormat)
	}
	if err != nil {
		return nil, errors.Wrap(err, "parsing client crt file")
	}

	crt, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("client cert file not of the right type")
	}

	return ssh.NewCertSigner(crt, signer)
}

// configures the host key callback based on the options
func setupHostKeyCallback(opt sshClientOptions) (ssh.HostKeyCallback, error) {
	if opt.knownHostsFile != "" {
		return knownhosts.New(opt.knownHostsFile)
	}

	if opt.insecure {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	knownHostsFile := findKnownHostsFile()
	if knownHostsFile != "" {
		return knownhosts.New(knownHostsFile)
	}

	return nil, errors.New("unable to find a known_hosts file")
}

// attempts to locate the known_hosts file
func findKnownHostsFile() string {
	if runtime.GOOS == "windows" {
		userProfile := os.Getenv("USERPROFILE")
		if userProfile != "" {
			return filepath.Join(userProfile, ".ssh", "known_hosts")
		}
	} else {
		home := os.Getenv("HOME")
		if home != "" {
			return filepath.Join(home, ".ssh", "known_hosts")
		}
	}
	return ""
}

// establishes the SSH connection
func createSSHClient(opt sshClientOptions, user, host string, signer ssh.Signer, hostKeyCallback ssh.HostKeyCallback) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	if opt.proxySocks5 != "" {
		return createProxyClient(opt.proxySocks5, host, config)
	}

	return ssh.Dial("tcp", host, config)
}

// creates an SSH client through a SOCKS5 proxy
func createProxyClient(proxyAddr, host string, config *ssh.ClientConfig) (*ssh.Client, error) {
	socksConnection, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, errors.Wrap(err, "could not create socks5 proxy "+proxyAddr)
	}

	conn, err := socksConnection.Dial("tcp", host)
	if err != nil {
		return nil, errors.Wrap(err, "could not create connection with socks")
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		return nil, errors.Wrap(err, "could not create socks5 proxy client "+proxyAddr)
	}

	return ssh.NewClient(clientConn, chans, reqs), nil
}

// runs the SSH session, either interactively or with a single command
func executeSSHSession(client *ssh.Client, opt sshClientOptions, command string) error {
	session, err := client.NewSession()
	if err != nil {
		return errors.Wrap(err, "creating SSH session")
	}
	defer session.Close()

	if opt.interactive {
		return runInteractiveSession(session)
	} else if command != "" {
		return runSingleCommand(session, command)
	} else {
		return errors.New("either a command or the interactive flag must be provided")
	}
}

// starts an interactive SSH session
func runInteractiveSession(session *ssh.Session) error {
	if err := session.RequestPty("xterm", 40, 80, ssh.TerminalModes{}); err != nil {
		return errors.Wrap(err, "requesting pseudo terminal")
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return errors.Wrap(err, "starting shell")
	}

	return session.Wait()
}

// executes a single command over SSH
func runSingleCommand(session *ssh.Session, command string) error {
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	return session.Run(command)
}
