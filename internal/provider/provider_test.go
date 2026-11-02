package provider

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb3oTKTAfHYZCz8xuo2tBahG3ZK0FUBwbxJmdIvrhWS test"

var testProviders = map[string]func() (tfprotov6.ProviderServer, error){
	"orionbelt": providerserver.NewProtocol6WithError(New("test")()),
}

// providerBlock configures the provider against g with the given compliance
// frameworks.
func providerBlock(g *fakeGateway, frameworks ...string) string {
	quoted := make([]string, len(frameworks))
	for i, f := range frameworks {
		quoted[i] = fmt.Sprintf("%q", f)
	}
	return fmt.Sprintf(`
provider "orionbelt" {
  url           = %q
  api_key       = %q
  insecure_http = true

  compliance {
    frameworks = [%s]
  }
}
`, g.server.URL, fakeAPIKey, strings.Join(quoted, ", "))
}

func future(d time.Duration) string {
	return time.Now().Add(d).UTC().Truncate(time.Second).Format(time.RFC3339)
}

func TestUserLifecycle(t *testing.T) {
	g := newFakeGateway(t)
	config := func(email string) string {
		return providerBlock(g, "soc2") + fmt.Sprintf(`
resource "orionbelt_user" "jane" {
  username   = "jane"
  email      = %q
  public_key = %q
}
`, email, testPublicKey)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: config("jane@example.com"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("orionbelt_user.jane", "role", "user"),
					resource.TestCheckResourceAttrSet("orionbelt_user.jane", "id"),
				),
			},
			{
				Config: config("jane@corp.example.com"),
				Check:  resource.TestCheckResourceAttr("orionbelt_user.jane", "email", "jane@corp.example.com"),
			},
			{
				ResourceName:      "orionbelt_user.jane",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestUserSharedAccountFailsPlan(t *testing.T) {
	g := newFakeGateway(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "soc2") + `
resource "orionbelt_user" "shared" {
  username = "admin"
  email    = "ops@example.com"
}
`,
			ExpectError: regexp.MustCompile(`(?s)no-shared-accounts.*SOC 2 CC6.1`),
		}},
	})
	if len(g.users) != 0 {
		t.Fatal("a user was created despite the violation")
	}
}

func TestPermissionCompliance(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("db-1")
	grant := func(remoteUser, expiry string) string {
		return providerBlock(g, "pci-dss-4") + fmt.Sprintf(`
resource "orionbelt_permission" "p" {
  user_id      = "user-x"
  machine_id   = %q
  access_type  = "ssh"
  remote_users = [%q]
  %s
}
`, machineID, remoteUser, expiry)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config:      grant("root", fmt.Sprintf("expires_at = %q", future(time.Hour))),
				ExpectError: regexp.MustCompile(`(?s)denied-remote-user.*PCI DSS 4.0 7.2.2`),
			},
			{
				Config:      grant("deploy", ""),
				ExpectError: regexp.MustCompile(`(?s)grant-expiry.*PCI DSS 4.0 7.2.4`),
			},
			{
				Config:      grant("deploy", fmt.Sprintf("expires_at = %q", future(40*24*time.Hour))),
				ExpectError: regexp.MustCompile(`grant-max-duration`),
			},
			{
				Config:      grant("deploy", `expires_at = "2020-01-01T00:00:00Z"`),
				ExpectError: regexp.MustCompile(`Grant already expired`),
			},
			{
				Config: grant("deploy", fmt.Sprintf("expires_at = %q", future(8*time.Hour))),
				Check:  resource.TestCheckResourceAttr("orionbelt_permission.p", "remote_users.0", "deploy"),
			},
		},
	})
	if n := g.permissionCount(machineID); n != 0 {
		t.Fatalf("%d grants left after destroy", n)
	}
}

func TestPermissionRefusesToAdoptExistingGrant(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("web-1")
	g.addGrant("user-x", machineID, "ssh", "deploy")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g) + fmt.Sprintf(`
resource "orionbelt_permission" "p" {
  user_id      = "user-x"
  machine_id   = %q
  access_type  = "ssh"
  remote_users = ["deploy"]
}
`, machineID),
			ExpectError: regexp.MustCompile(`Grant already exists`),
		}},
	})
}

func TestMachineAccessRevokesOutOfBandGrants(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("web-1")
	config := providerBlock(g, "soc2") + fmt.Sprintf(`
resource "orionbelt_machine_access" "web" {
  machine_id = %q

  grant {
    user_id      = "user-a"
    access_type  = "ssh"
    remote_users = ["deploy"]
    expires_at   = %q
  }

  grant {
    user_id      = "user-b"
    access_type  = "rdp"
    remote_users = ["Administrator"]
    expires_at   = %q
  }
}
`, machineID, future(24*time.Hour), future(48*time.Hour))

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(*terraform.State) error {
					if n := g.permissionCount(machineID); n != 2 {
						return fmt.Errorf("want 2 grants, got %d", n)
					}
					return nil
				},
			},
			{
				// Someone grants root in the console; the next plan shows drift.
				PreConfig:          func() { g.addGrant("user-c", machineID, "ssh", "root") },
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config,
				Check: func(*terraform.State) error {
					if n := g.permissionCount(machineID); n != 2 {
						return fmt.Errorf("out-of-band grant not revoked: %d grants", n)
					}
					return nil
				},
			},
		},
	})
}

func TestMachineAccessRejectsDuplicates(t *testing.T) {
	g := newFakeGateway(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g) + `
resource "orionbelt_machine_access" "web" {
  machine_id = "machine-1"
  grant {
    user_id      = "user-a"
    access_type  = "ssh"
    remote_users = ["deploy"]
  }
  grant {
    user_id      = "user-a"
    access_type  = "ssh"
    remote_users = ["www"]
  }
}
`,
			ExpectError: regexp.MustCompile(`Duplicate grant`),
		}},
	})
}

func TestAgentRegistersAndRendersCloudInit(t *testing.T) {
	g := newFakeGateway(t)
	g.hostCA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl host-ca"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "iso27001", "pci-dss-4") + fmt.Sprintf(`
resource "orionbelt_agent" "web" {
  name                = "web-1"
  public_key          = %q
  tags                = { env = "prod" }
  install_version     = "v1.4.0"
  private_key_command = "aws secretsmanager get-secret-value --secret-id orion/web-1 --query SecretString --output text"
}
`, testPublicKey),
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("orionbelt_agent.web", "gateway_host", "gw.example.com"),
				resource.TestCheckResourceAttr("orionbelt_agent.web", "gateway_port", "2222"),
				resource.TestCheckResourceAttr("orionbelt_agent.web", "archive_on_destroy", "true"),
				resource.TestMatchResourceAttr("orionbelt_agent.web", "agent_yaml", regexp.MustCompile(`strict_host_key_checking: "?yes`)),
				resource.TestMatchResourceAttr("orionbelt_agent.web", "cloud_init", regexp.MustCompile(`^#cloud-config`)),
				resource.TestCheckResourceAttrSet("orionbelt_agent.web", "host_certificate"),
			),
		}},
	})

	if log := g.deleteLog(); len(log) != 1 || !strings.HasPrefix(log[0], "archive machine") {
		t.Fatalf("destroy should archive, got %v", log)
	}
}

func TestAgentWithoutTrustAnchorFailsUnderISO(t *testing.T) {
	g := newFakeGateway(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "iso27001") + fmt.Sprintf(`
resource "orionbelt_agent" "web" {
  name       = "web-1"
  public_key = %q
}
`, testPublicKey),
			ExpectError: regexp.MustCompile(`(?s)host-ca.*ISO/IEC 27001:2022 A.8.20`),
		}},
	})
}

func TestAgentDeleteRecordingsFailsUnderSOC2(t *testing.T) {
	g := newFakeGateway(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "soc2") + fmt.Sprintf(`
resource "orionbelt_agent" "web" {
  name               = "web-1"
  public_key         = %q
  archive_on_destroy = false
}
`, testPublicKey),
			ExpectError: regexp.MustCompile(`(?s)retain-evidence.*SOC 2 CC7.2`),
		}},
	})
}

func TestAgentRejectsPrivateKey(t *testing.T) {
	g := newFakeGateway(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g) + `
resource "orionbelt_agent" "web" {
  name       = "web-1"
  public_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
}
`,
			ExpectError: regexp.MustCompile(`Private key given`),
		}},
	})
}

func TestRiskPolicyCompliance(t *testing.T) {
	g := newFakeGateway(t)
	config := func(requireMFA bool) string {
		return providerBlock(g, "pci-dss-4") + fmt.Sprintf(`
resource "orionbelt_risk_policy" "this" {
  auto_approve {
    max_sensitivity      = "low"
    max_duration_seconds = 3600
    require_mfa          = %t
    remote_users         = ["deploy"]
  }
  escalate {
    without_mfa = true
  }
}
`, requireMFA)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config:      config(false),
				ExpectError: regexp.MustCompile(`(?s)auto-approval must require MFA.*PCI DSS 4.0 8.4.2`),
			},
			{
				Config: config(true),
				Check:  resource.TestCheckResourceAttr("orionbelt_risk_policy.this", "auto_approve.require_mfa", "true"),
			},
		},
	})
	if g.riskPolicy.AutoApprove.Enabled || g.riskPolicy.Escalate.Enabled {
		t.Fatal("destroy should turn the policy off")
	}
}

func TestAccessReviewFindsOutOfBandViolations(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("db-1")
	g.addGrant("user-x", machineID, "ssh", "root")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "pci-dss-4") + `
data "orionbelt_access_review" "all" {}
data "orionbelt_compliance_profile" "this" {}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("data.orionbelt_access_review.all", "compliant", "false"),
				resource.TestCheckResourceAttr("data.orionbelt_access_review.all", "entries.#", "1"),
				resource.TestCheckResourceAttr("data.orionbelt_access_review.all", "findings.#", "2"),
				resource.TestCheckResourceAttr("data.orionbelt_compliance_profile.this", "frameworks.0", "pci-dss-4"),
				func(s *terraform.State) error {
					attrs := s.RootModule().Resources["data.orionbelt_access_review.all"].Primary.Attributes
					rules := []string{attrs["findings.0.rule"], attrs["findings.1.rule"]}
					slices.Sort(rules)
					if strings.Join(rules, ",") != "denied-remote-user,grant-expiry" {
						return fmt.Errorf("findings = %v", rules)
					}
					return nil
				},
			),
		}},
	})
}

func TestProviderRejectsUnknownFramework(t *testing.T) {
	g := newFakeGateway(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config:      providerBlock(g, "hipaa") + `data "orionbelt_compliance_profile" "this" {}`,
			ExpectError: regexp.MustCompile(`unknown compliance framework "hipaa"`),
		}},
	})
}

func TestProviderRejectsPlainHTTP(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: `
provider "orionbelt" {
  url     = "http://gw.example.com"
  api_key = "k"
}
data "orionbelt_gateway" "this" {}
`,
			ExpectError: regexp.MustCompile(`clear text`),
		}},
	})
}

func TestAgentKeyRotationArchivesAndFreesName(t *testing.T) {
	g := newFakeGateway(t)
	config := func(key string) string {
		return providerBlock(g, "soc2") + fmt.Sprintf(`
resource "orionbelt_agent" "web" {
  name       = "web-1"
  public_key = %q
}
`, key)
	}
	rotated := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl rotated"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: config(testPublicKey)},
			{
				Config: config(rotated),
				Check:  resource.TestCheckResourceAttr("orionbelt_agent.web", "name", "web-1"),
			},
		},
	})

	g.mu.Lock()
	defer g.mu.Unlock()
	archived := 0
	for _, m := range g.machines {
		if !m.IsActive && strings.HasPrefix(m.Name, "web-1-archived-") {
			archived++
		}
	}
	if archived != 2 {
		t.Fatalf("want both agents archived under renamed names, got %d", archived)
	}
}

func TestPermissionUpdateAndNonUTCExpiry(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("web-1")
	local := time.FixedZone("CET", 3600)
	expiry := time.Now().Add(48 * time.Hour).In(local).Truncate(time.Second).Format(time.RFC3339)
	config := func(remoteUser string) string {
		return providerBlock(g, "soc2") + fmt.Sprintf(`
resource "orionbelt_permission" "p" {
  user_id      = "user-x"
  machine_id   = %q
  access_type  = "ssh"
  remote_users = [%q]
  expires_at   = %q
}
`, machineID, remoteUser, expiry)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: config("deploy"),
				Check:  resource.TestCheckResourceAttr("orionbelt_permission.p", "expires_at", expiry),
			},
			{
				Config: config("www-data"),
				Check:  resource.TestCheckResourceAttr("orionbelt_permission.p", "remote_users.0", "www-data"),
			},
			{Config: config("www-data"), PlanOnly: true},
		},
	})
}

func TestAgentImportThenDestroyArchives(t *testing.T) {
	g := newFakeGateway(t)
	config := providerBlock(g) + fmt.Sprintf(`
resource "orionbelt_agent" "web" {
  name       = "web-1"
  public_key = %q
}
`, testPublicKey)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: config},
			{
				ResourceName:            "orionbelt_agent.web",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"public_key", "agent_yaml", "cloud_init", "host_certificate", "host_ca_public_key", "gateway_host", "gateway_port"},
			},
		},
	})
	for _, entry := range g.deleteLog() {
		if strings.HasPrefix(entry, "delete machine") {
			t.Fatalf("a machine was hard-deleted: %v", g.deleteLog())
		}
	}
}

func TestPermissionRemoteUsersUnknownAtPlan(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("web-1")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "soc2") + fmt.Sprintf(`
resource "terraform_data" "account" {
  input = "deploy"
}

resource "orionbelt_permission" "p" {
  user_id      = "user-x"
  machine_id   = %q
  access_type  = "ssh"
  remote_users = [terraform_data.account.output]
  expires_at   = %q
}
`, machineID, future(time.Hour)),
			Check: resource.TestCheckResourceAttr("orionbelt_permission.p", "remote_users.0", "deploy"),
		}},
	})
}

func TestPermissionClearsRemoteUsers(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("desk-1")
	config := func(users string) string {
		return providerBlock(g) + fmt.Sprintf(`
resource "orionbelt_permission" "p" {
  user_id     = "user-x"
  machine_id  = %q
  access_type = "rdp"
  %s
}
`, machineID, users)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: config(`remote_users = ["Administrator"]`)},
			{
				Config: config(""),
				Check:  resource.TestCheckNoResourceAttr("orionbelt_permission.p", "remote_users.#"),
			},
			{Config: config(""), PlanOnly: true},
		},
	})
}

func TestSSHGrantNeedsRemoteUsers(t *testing.T) {
	g := newFakeGateway(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g) + `
resource "orionbelt_permission" "p" {
  user_id     = "user-x"
  machine_id  = "m"
  access_type = "ssh"
}
`,
			ExpectError: regexp.MustCompile(`Missing remote_users`),
		}},
	})
}

func TestAgentEmptyTagsAndNameValidation(t *testing.T) {
	g := newFakeGateway(t)
	agent := func(name, tags string) string {
		return providerBlock(g) + fmt.Sprintf(`
resource "orionbelt_agent" "web" {
  name       = %q
  public_key = %q
  %s
}
`, name, testPublicKey, tags)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: agent("web 1", ""), ExpectError: regexp.MustCompile(`letters, digits`)},
			{Config: agent("web-1", "tags = {}")},
			{Config: agent("web-1", "tags = {}"), PlanOnly: true},
		},
	})
}
