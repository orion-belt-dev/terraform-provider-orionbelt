package agentconfig

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func baseAgent() Agent {
	return Agent{
		Name:        "web-1",
		Tags:        map[string]string{"env": "prod"},
		GatewayHost: "gw.example.com",
		GatewayPort: 2222,
	}
}

func TestAgentYAMLWithHostCA(t *testing.T) {
	a := baseAgent()
	a.HostCAPublicKey = "ssh-ed25519 AAAAC3NzaCA host-ca\n"
	out, err := AgentYAML(a)
	if err != nil {
		t.Fatal(err)
	}

	var f agentFile
	if err := yaml.Unmarshal([]byte(out), &f); err != nil {
		t.Fatalf("output is not valid YAML: %v\n%s", err, out)
	}
	if f.Server.Host != "gw.example.com" || f.Server.Port != 2222 || f.Agent.Name != "web-1" {
		t.Fatalf("unexpected config: %+v", f)
	}
	if f.Auth.StrictHostKeyChecking != "yes" {
		t.Fatalf("strict_host_key_checking = %q, want yes with a host CA", f.Auth.StrictHostKeyChecking)
	}
	if f.Auth.HostCAPublicKey != "ssh-ed25519 AAAAC3NzaCA host-ca" {
		t.Fatalf("host_ca_public_key = %q", f.Auth.HostCAPublicKey)
	}
}

func TestAgentYAMLWithoutTrustAnchorUsesTOFU(t *testing.T) {
	out, err := AgentYAML(baseAgent())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "strict_host_key_checking: ask") {
		t.Fatalf("want ask mode:\n%s", out)
	}
}

func TestAgentYAMLEscapesValues(t *testing.T) {
	a := baseAgent()
	a.Tags = map[string]string{"note": "a: b\nserver:\n  host: evil"}
	out, err := AgentYAML(a)
	if err != nil {
		t.Fatal(err)
	}
	var f agentFile
	if err := yaml.Unmarshal([]byte(out), &f); err != nil {
		t.Fatal(err)
	}
	if f.Server.Host != "gw.example.com" {
		t.Fatalf("tag value changed the server host: %q", f.Server.Host)
	}
}

func TestCloudInitRequiresKeyCommand(t *testing.T) {
	if _, err := CloudInit(baseAgent(), Install{}); err == nil {
		t.Fatal("want error without private_key_command")
	}
}

func TestCloudInit(t *testing.T) {
	a := baseAgent()
	a.HostCertificate = "ssh-ed25519-cert-v01@openssh.com AAAA cert"
	a.GatewayHostKey = "ssh-ed25519 AAAAgw"
	out, err := CloudInit(a, Install{
		Version:           "v1.4.0",
		PrivateKeyCommand: "aws secretsmanager get-secret-value --secret-id agent/web-1 --query SecretString --output text",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "#cloud-config\n") {
		t.Fatalf("missing header:\n%s", out)
	}

	var cfg cloudConfig
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("not valid YAML: %v", err)
	}
	paths := map[string]cloudFile{}
	for _, f := range cfg.WriteFiles {
		paths[f.Path] = f
	}
	if _, ok := paths[configPath]; !ok {
		t.Error("agent.yaml not written")
	}
	if paths[certPath].Content != a.HostCertificate+"\n" {
		t.Errorf("certificate = %q", paths[certPath].Content)
	}
	if paths[knownHosts].Content != "[gw.example.com]:2222 ssh-ed25519 AAAAgw\n" {
		t.Errorf("known_hosts = %q", paths[knownHosts].Content)
	}
	if _, ok := paths[keyPath]; ok {
		t.Error("private key must never be written by cloud-init")
	}

	if len(cfg.RunCmd) != 1 {
		t.Fatalf("want one runcmd script so a failed step stops the rest: %v", cfg.RunCmd)
	}
	script := cfg.RunCmd[0][2]
	for _, want := range []string{"set -eu", "umask 077", "test -s ", "--version 'v1.4.0'", "--proto '=https'"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Index(script, "test -s") > strings.Index(script, "orion-belt-install.sh agent") {
		t.Error("the key must be checked before the agent is installed")
	}
}

func TestCloudInitScriptRuns(t *testing.T) {
	dir := t.TempDir()
	keyFile := dir + "/key"
	out, err := CloudInit(baseAgent(), Install{PrivateKeyCommand: "echo secret # trailing comment"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg cloudConfig
	if err := yaml.Unmarshal([]byte(strings.TrimPrefix(out, "#cloud-config\n")), &cfg); err != nil {
		t.Fatal(err)
	}
	// Run only the key-fetch part, pointed at a temp file.
	script := strings.ReplaceAll(cfg.RunCmd[0][2], keyPath, keyFile)
	keyPart, _, found := strings.Cut(script, "curl ")
	if !found {
		t.Fatalf("no install step in script:\n%s", script)
	}
	script = keyPart
	if err := exec.Command("sh", "-c", script).Run(); err != nil {
		t.Fatalf("key fetch failed: %v\n%s", err, script)
	}
	got, err := os.ReadFile(keyFile)
	if err != nil || strings.TrimSpace(string(got)) != "secret" {
		t.Fatalf("key = %q, %v", got, err)
	}

	failing := strings.ReplaceAll(script, "echo secret # trailing comment", "false")
	if err := exec.Command("sh", "-c", failing+"echo should-not-run > "+dir+"/ran").Run(); err == nil {
		t.Fatal("a failing key command must stop the script")
	}
	if _, err := os.Stat(dir + "/ran"); err == nil {
		t.Fatal("later steps ran after the key command failed")
	}
}

func TestKnownHostsLineDefaultPort(t *testing.T) {
	a := baseAgent()
	a.GatewayPort = 22
	a.GatewayHostKey = "ssh-ed25519 AAAA"
	if got := KnownHostsLine(a); got != "gw.example.com ssh-ed25519 AAAA" {
		t.Fatalf("got %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Fatalf("got %s", got)
	}
}
