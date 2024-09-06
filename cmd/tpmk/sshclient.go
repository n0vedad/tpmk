package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

	if opt.insecure && opt.knownHostsFile != "" {
		return errors.New("can't use -k with -s")
	}
	if opt.crtFile != "" && opt.crtHandle != "" {
		return errors.New("can use either -c or -i, not both")
	}

	s := strings.Split(remote, "@")
	if len(s) != 2 {
		return errors.New("require user@host:port for remote endpoint")
	}
	user := s[0]
	host := s[1]

	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return errors.Wrap(err, "opening "+opt.device)
	}
	defer dev.Close()

	pk, err := tpmk.NewRSAPrivateKey(dev, keyHandle, opt.keyPassword)
	if err != nil {
		return errors.Wrap(err, "accessing key")
	}
	signer, err := ssh.NewSignerFromSigner(pk)
	if err != nil {
		return errors.Wrap(err, "invalid key")
	}

	if opt.crtFile != "" || opt.crtHandle != "" {
		var b []byte
		var err error
		if opt.crtHandle != "" {
			crtHandle, err := parseHandle(opt.crtHandle)
			if err != nil {
				return err
			}
			b, err = tpmk.NVRead(dev, crtHandle, "")
			if err != nil {
				return errors.Wrap(err, "reading crt from TPM")
			}
		} else {
			b, err = ioutil.ReadFile(opt.crtFile)
			if err != nil {
				return errors.Wrap(err, "reading client crt file")
			}
		}

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

		crt, ok := pub.(*ssh.Certificate)
		if !ok {
			return errors.New("client cert file not of the right type")
		}

		signer, err = ssh.NewCertSigner(crt, signer)
		if err != nil {
			return err
		}
	}

	var hostKeyCallback ssh.HostKeyCallback
	switch {
	case opt.knownHostsFile != "":
		hostKeyCallback, err = knownhosts.New(opt.knownHostsFile)
		if err != nil {
			return errors.Wrap(err, "reading host key file")
		}
	case opt.insecure:
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	default:
		if home := os.Getenv("HOME"); home != "" {
			f := filepath.Join(home, ".ssh/known_hosts")
			hostKeyCallback, err = knownhosts.New(f)
			if err == nil {
				break
			}
			if !os.IsNotExist(err) {
				return errors.Wrap(err, "reading known_hosts file: "+f)
			}
		}
		hostKeyCallback, err = knownhosts.New("/etc/ssh/ssh_known_hosts")
		if err != nil {
			return errors.New("unable to find a known_hosts file")
		}
	}

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
