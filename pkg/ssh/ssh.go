package ssh

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/alexhunt7/ssher"
	"github.com/kballard/go-shellquote"
	"github.com/loft-sh/devpod-provider-ssh/pkg/options"
	"github.com/loft-sh/devpod/pkg/log"
	sshagent "github.com/xanzy/ssh-agent"
	"golang.org/x/crypto/ssh"
)

type SSHProvider struct {
	Config           *options.Options
	Log              log.Logger
	WorkingDirectory string
}

func NewProvider(logs log.Logger) (*SSHProvider, error) {
	config, err := options.FromEnv()
	if err != nil {
		return nil, err
	}

	// create provider
	provider := &SSHProvider{
		Config: config,
		Log:    logs,
	}

	return provider, nil
}

func returnSSHError(provider *SSHProvider, command string) error {
	sshError := "Please make sure you have configured the correct SSH host\nand the following command can be executed on your system:\n"

	sshcmd, err := getSSHCommand(provider)
	if err != nil {
		return err
	}

	return fmt.Errorf(sshError + "ssh " + strings.Join(sshcmd, " ") + " " + command)
}

func getSSHCommand(provider *SSHProvider) ([]string, error) {
	result := []string{"-oStrictHostKeyChecking=no", "-oBatchMode=yes"}

	if provider.Config.Port != "22" {
		result = append(result, []string{"-p", provider.Config.Port}...)
	}

	if provider.Config.ExtraFlags != "" {
		flags, err := shellquote.Split(provider.Config.ExtraFlags)
		if err != nil {
			return nil, fmt.Errorf("error managing EXTRA_ARGS, %v", err)
		}

		result = append(result, flags...)
	}

	result = append(result, provider.Config.Host)
	return result, nil
}

func execSSHCommand(provider *SSHProvider, command string, output io.Writer) error {
	sshConfig, hostPort, err := ssher.ClientConfig(provider.Config.Host, "")
	if err != nil {
		return fmt.Errorf("ssh client config for %s: %+v", provider.Config.Host, err)
	}
	if sshagent.Available() {
		agent, _, err := sshagent.New()
		if err != nil {
			return fmt.Errorf("ssh agent: %+v", err)
		}
		signers, err := agent.Signers()
		if err != nil {
			return fmt.Errorf("ssh signers: %+v", err)
		}
		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}
		sshConfig.User = "nomeaning"
	}
	conn, err := ssh.Dial("tcp", hostPort, sshConfig)
	if err != nil {
		return fmt.Errorf("ssh dial: %v", err)
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("ssh new session: %v", err)
	}
	defer session.Close()
	session.Stdin = os.Stdin
	session.Stdout = output
	session.Stderr = os.Stderr
	err = session.Run(command)
	if err != nil {
		return err
	}
	return nil
}

func Init(provider *SSHProvider) error {
	out := new(bytes.Buffer)
	// check that we can do outputs
	err := execSSHCommand(provider, "echo Devpod Test", out)
	if err != nil {
		return returnSSHError(provider, "echo Devpod Test")
	}
	if out.String() != "Devpod Test\n" {
		return fmt.Errorf("error: ssh output mismatch")
	}

	// We only support running on Linux ssh servers
	out = new(bytes.Buffer)
	err = execSSHCommand(provider, "uname", out)
	if err != nil {
		return returnSSHError(provider, "uname")
	}
	if out.String() != "Linux\n" {
		fmt.Println(out.String())
		return fmt.Errorf("error: SSH provider only works on Linux servers")
	}

	// If we're root, we won't have problems
	out = new(bytes.Buffer)
	err = execSSHCommand(provider, "id -ru", out)
	if err != nil {
		return returnSSHError(provider, "id -ru")
	}
	if out.String() == "0\n" {
		return nil
	}

	// check that we have access to AGENT_PATH
	out = new(bytes.Buffer)
	agentDir := path.Dir(provider.Config.AgentPath)
	err1 := execSSHCommand(provider, "mkdir -p "+agentDir, out)
	err2 := execSSHCommand(provider, "test -w "+agentDir, out)
	if err1 != nil || err2 != nil {
		err = execSSHCommand(provider, "sudo -nl", out)
		if err != nil {
			return fmt.Errorf(
				agentDir + " is not writable, passwordless sudo or root user required",
			)
		}
	}

	// check that we have access to DOCKER_PATH
	err = execSSHCommand(provider, provider.Config.DockerPath+" ps", out)
	if err != nil {
		err = execSSHCommand(provider, "sudo -nl", out)
		if err != nil {
			return fmt.Errorf(
				provider.Config.DockerPath + " not found, passwordless sudo or root user required",
			)
		}
	}

	return nil
}

func Command(provider *SSHProvider, command string) error {
	return execSSHCommand(provider, command, os.Stdout)
}
