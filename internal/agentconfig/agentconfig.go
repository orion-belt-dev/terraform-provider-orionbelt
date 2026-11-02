// Package agentconfig renders the files an Orion Belt agent needs: its
// agent.yaml and a cloud-init document that installs and starts it.
package agentconfig

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	configDir    = "/etc/orion-belt"
	configPath   = configDir + "/agent.yaml"
	keyPath      = configDir + "/agent_key"
	certPath     = configDir + "/agent_key-cert.pub"
	knownHosts   = configDir + "/known_hosts"
	installerURL = "https://pkgs.orion-belt.dev/install.sh"
)

// Agent describes one agent and the gateway it joins.
type Agent struct {
	Name            string
	Tags            map[string]string
	GatewayHost     string
	GatewayPort     int
	HostCertificate string
	HostCAPublicKey string
	// GatewayHostKey pins the gateway's SSH host key (authorized_keys
	// format) for gateways without a host CA.
	GatewayHostKey string
}

// Install controls how cloud-init installs the agent.
type Install struct {
	// Version pins the release, e.g. "v1.4.0". Empty installs the latest.
	Version string
	// PrivateKeyCommand prints the agent's private key on stdout. It runs on
	// the host at first boot, so the key never passes through Terraform.
	PrivateKeyCommand string
}

type agentFile struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	Agent struct {
		Name string            `yaml:"name"`
		Tags map[string]string `yaml:"tags,omitempty"`
	} `yaml:"agent"`
	Auth struct {
		KeyFile               string `yaml:"key_file"`
		KnownHosts            string `yaml:"known_hosts"`
		StrictHostKeyChecking string `yaml:"strict_host_key_checking"`
		HostCAPublicKey       string `yaml:"host_ca_public_key,omitempty"`
	} `yaml:"auth"`
}

// AgentYAML renders /etc/orion-belt/agent.yaml. With a host CA or a pinned
// gateway host key the agent refuses unknown keys. With neither it falls
// back to trust on first use.
func AgentYAML(a Agent) (string, error) {
	var f agentFile
	f.Server.Host = a.GatewayHost
	f.Server.Port = a.GatewayPort
	f.Agent.Name = a.Name
	f.Agent.Tags = a.Tags
	f.Auth.KeyFile = keyPath
	f.Auth.KnownHosts = knownHosts
	f.Auth.StrictHostKeyChecking = "ask"
	if a.HostCAPublicKey != "" || a.GatewayHostKey != "" {
		f.Auth.StrictHostKeyChecking = "yes"
	}
	f.Auth.HostCAPublicKey = strings.TrimSpace(a.HostCAPublicKey)

	out, err := yaml.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("render agent.yaml: %w", err)
	}
	return string(out), nil
}

type cloudConfig struct {
	WriteFiles []cloudFile `yaml:"write_files"`
	RunCmd     [][]string  `yaml:"runcmd"`
}

type cloudFile struct {
	Path        string `yaml:"path"`
	Permissions string `yaml:"permissions"`
	Owner       string `yaml:"owner"`
	Content     string `yaml:"content"`
}

// CloudInit renders a #cloud-config document that writes the agent's
// configuration and certificate, fetches its private key with
// PrivateKeyCommand, installs the agent with the signed installer and starts
// it. It contains no secrets.
func CloudInit(a Agent, in Install) (string, error) {
	if strings.TrimSpace(in.PrivateKeyCommand) == "" {
		return "", fmt.Errorf("private_key_command is required to render cloud-init")
	}
	agentYAML, err := AgentYAML(a)
	if err != nil {
		return "", err
	}

	cfg := cloudConfig{}
	cfg.WriteFiles = append(cfg.WriteFiles, cloudFile{
		Path:        configPath,
		Permissions: "0640",
		Owner:       "root:root",
		Content:     agentYAML,
	})
	if a.GatewayHostKey != "" {
		cfg.WriteFiles = append(cfg.WriteFiles, cloudFile{
			Path:        knownHosts,
			Permissions: "0644",
			Owner:       "root:root",
			Content:     KnownHostsLine(a) + "\n",
		})
	}
	if a.HostCertificate != "" {
		cfg.WriteFiles = append(cfg.WriteFiles, cloudFile{
			Path:        certPath,
			Permissions: "0644",
			Owner:       "root:root",
			Content:     strings.TrimSpace(a.HostCertificate) + "\n",
		})
	}

	// One script so a failed step stops the rest: an agent must not start
	// without its key. The command sits on its own lines so a trailing
	// comment in it cannot swallow the closing parenthesis.
	installArgs := "agent"
	if in.Version != "" {
		installArgs += " --version " + shellQuote(in.Version)
	}
	script := strings.Join([]string{
		"set -eu",
		"umask 077",
		"trap 'rm -f " + keyPath + ".tmp /run/orion-belt-install.sh' EXIT",
		"(",
		in.PrivateKeyCommand,
		") > " + keyPath + ".tmp",
		"test -s " + keyPath + ".tmp",
		"mv " + keyPath + ".tmp " + keyPath,
		"curl -fsSL --proto '=https' --tlsv1.2 -o /run/orion-belt-install.sh " + installerURL,
		"sh /run/orion-belt-install.sh " + installArgs,
		"/usr/lib/orion-belt/orion-belt-agent-service setup",
	}, "\n")
	cfg.RunCmd = [][]string{{"sh", "-c", script}}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("render cloud-init: %w", err)
	}
	return "#cloud-config\n" + string(out), nil
}

// KnownHostsLine renders the known_hosts entry that pins the gateway.
func KnownHostsLine(a Agent) string {
	host := a.GatewayHost
	if a.GatewayPort != 22 {
		host = fmt.Sprintf("[%s]:%d", a.GatewayHost, a.GatewayPort)
	}
	return host + " " + strings.TrimSpace(a.GatewayHostKey)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
