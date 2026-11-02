package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
	"golang.org/x/crypto/ssh"
)

// Acceptance tests run against a real gateway:
//
//	TF_ACC=1 ORIONBELT_URL=http://localhost:8080 ORIONBELT_API_KEY=... \
//	  ORIONBELT_INSECURE_HTTP=1 go test ./internal/provider -run TestAcc
//
// They create and destroy their own users and agents, named with a
// timestamp suffix so reruns do not collide.

func accPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("ORIONBELT_URL") == "" || os.Getenv("ORIONBELT_API_KEY") == "" {
		t.Fatal("ORIONBELT_URL and ORIONBELT_API_KEY must be set for acceptance tests")
	}
}

func accProviderBlock(frameworks string) string {
	insecure := os.Getenv("ORIONBELT_INSECURE_HTTP") != ""
	return fmt.Sprintf(`
provider "orionbelt" {
  insecure_http = %t
  compliance {
    frameworks = [%s]
  }
}
`, insecure, frameworks)
}

func newPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestAccEndToEnd(t *testing.T) {
	suffix := fmt.Sprintf("%d", time.Now().Unix())
	publicKey := newPublicKey(t)
	config := func(remoteUser string) string {
		return accProviderBlock(`"soc2"`) + fmt.Sprintf(`
resource "orionbelt_user" "eng" {
  username = "acc-eng-%[1]s"
  email    = "acc-eng-%[1]s@example.com"
}

resource "orionbelt_agent" "web" {
  name       = "acc-web-%[1]s"
  public_key = %[2]q
  tags       = { env = "acc" }
}

resource "orionbelt_machine_access" "web" {
  machine_id = orionbelt_agent.web.id
  grant {
    user_id      = orionbelt_user.eng.id
    access_type  = "ssh"
    remote_users = [%[3]q]
    expires_at   = %[4]q
  }
}

data "orionbelt_access_review" "web" {
  machine_ids = [orionbelt_agent.web.id]
  depends_on  = [orionbelt_machine_access.web]
}
`, suffix, publicKey, remoteUser, future(24*time.Hour))
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: config("deploy"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("orionbelt_agent.web", "agent_yaml"),
					resource.TestCheckResourceAttr("orionbelt_machine_access.web", "grant.#", "1"),
					resource.TestCheckResourceAttr("data.orionbelt_access_review.web", "compliant", "true"),
				),
			},
			{
				Config: config("www-data"),
				Check:  resource.TestCheckResourceAttr("orionbelt_machine_access.web", "grant.0.remote_users.0", "www-data"),
			},
			{
				ResourceName:      "orionbelt_user.eng",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccComplianceBlocksApply(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: accProviderBlock(`"pci-dss-4"`) + `
resource "orionbelt_user" "shared" {
  username = "admin"
  email    = ""
}
`,
			ExpectError: regexp.MustCompile(`no-shared-accounts`),
		}},
	})
}

func accClient(t *testing.T) *sdk.Client {
	t.Helper()
	c, err := sdk.NewClient(os.Getenv("ORIONBELT_URL"), sdk.WithAPIKey(os.Getenv("ORIONBELT_API_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAccDriftRotationAndPolicy(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC to run acceptance tests")
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	firstKey := newPublicKey(t)
	secondKey := newPublicKey(t)
	expiry := future(24 * time.Hour)
	hostKey := gatewayHostKey(t)
	var machineID, intruderID string

	config := func(key string) string {
		return accProviderBlock(`"pci-dss-4"`) + fmt.Sprintf(`
resource "orionbelt_user" "eng" {
  username = "acc-eng-%[1]s"
  email    = "acc-eng-%[1]s@example.com"
}

resource "orionbelt_agent" "db" {
  name             = "acc-db-%[1]s"
  public_key       = %[2]q
  gateway_host_key = %[4]q
}

resource "orionbelt_machine_access" "db" {
  machine_id = orionbelt_agent.db.id
  grant {
    user_id      = orionbelt_user.eng.id
    access_type  = "ssh"
    remote_users = ["postgres"]
    expires_at   = %[3]q
  }
}

resource "orionbelt_risk_policy" "this" {
  auto_approve {
    max_sensitivity      = "low"
    max_duration_seconds = 3600
    require_mfa          = true
    remote_users         = ["deploy"]
  }
  escalate {
    without_mfa = true
  }
}
`, suffix, key, expiry, hostKey)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: config(firstKey),
				Check: func(s *terraform.State) error {
					machineID = s.RootModule().Resources["orionbelt_agent.db"].Primary.ID
					return nil
				},
			},
			{
				PreConfig: func() {
					intruder, err := accClient(t).CreateUser(t.Context(), sdk.CreateUserRequest{
						Username: "acc-intruder-" + suffix, Email: "intruder-" + suffix + "@example.com", Role: "user",
					})
					if err != nil {
						t.Fatal(err)
					}
					intruderID = intruder.ID
					_, err = accClient(t).GrantPermission(t.Context(), sdk.GrantPermissionRequest{
						UserID: intruderID, MachineID: machineID, AccessType: "ssh", RemoteUsers: []string{"root"},
					})
					if err != nil {
						t.Fatal(err)
					}
				},
				Config:             config(firstKey),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: config(firstKey),
				Check: func(*terraform.State) error {
					perms, err := accClient(t).GetMachinePermissions(t.Context(), machineID)
					if err != nil {
						return err
					}
					for _, p := range perms {
						if p.UserID == intruderID {
							return fmt.Errorf("out-of-band grant %s survived apply", p.ID)
						}
					}
					return nil
				},
			},
			{
				Config: config(secondKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("orionbelt_agent.db", "name", "acc-db-"+suffix),
					func(s *terraform.State) error {
						if s.RootModule().Resources["orionbelt_agent.db"].Primary.ID == machineID {
							return fmt.Errorf("key rotation did not replace the agent")
						}
						return nil
					},
				),
			},
		},
	})

	if intruderID != "" {
		_ = accClient(t).DeleteUser(t.Context(), intruderID)
	}
}

// gatewayHostKey reads the gateway's SSH host key from a handshake, standing
// in for the out-of-band copy an operator would pin.
func gatewayHostKey(t *testing.T) string {
	t.Helper()
	info, err := accClient(t).GetGatewayInfo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	host, port := info.PublicSSHHost, info.PublicSSHPort
	if host == "" {
		host, port = info.SSHHost, info.SSHPort
	}
	var key ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return nil
		},
		Timeout: 5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)), cfg)
	if err == nil {
		conn.Close()
	}
	if key == nil {
		t.Fatalf("could not read gateway host key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestAccPermissionUpdate(t *testing.T) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	publicKey := newPublicKey(t)
	expiry := time.Now().Add(48 * time.Hour).In(time.FixedZone("CET", 3600)).Truncate(time.Second).Format(time.RFC3339)
	config := func(remoteUser string) string {
		return accProviderBlock(`"soc2"`) + fmt.Sprintf(`
resource "orionbelt_user" "eng" {
  username = "acc-perm-%[1]s"
  email    = "acc-perm-%[1]s@example.com"
}

resource "orionbelt_agent" "web" {
  name       = "acc-permhost-%[1]s"
  public_key = %[2]q
}

resource "orionbelt_permission" "p" {
  user_id      = orionbelt_user.eng.id
  machine_id   = orionbelt_agent.web.id
  access_type  = "ssh"
  remote_users = [%[3]q]
  expires_at   = %[4]q
}
`, suffix, publicKey, remoteUser, expiry)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
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

func TestAccAccessReviewFlagsOutOfBandGrant(t *testing.T) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	config := accProviderBlock(`"soc2"`) + fmt.Sprintf(`
resource "orionbelt_user" "eng" {
  username = "acc-review-%[1]s"
  email    = "acc-review-%[1]s@example.com"
}

resource "orionbelt_agent" "web" {
  name       = "acc-reviewhost-%[1]s"
  public_key = %[2]q
}

data "orionbelt_access_review" "web" {
  machine_ids = [orionbelt_agent.web.id]
}
`, suffix, newPublicKey(t))

	var userID, machineID string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { accPreCheck(t) },
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.orionbelt_access_review.web", "compliant", "true"),
					func(s *terraform.State) error {
						userID = s.RootModule().Resources["orionbelt_user.eng"].Primary.ID
						machineID = s.RootModule().Resources["orionbelt_agent.web"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					_, err := accClient(t).GrantPermission(t.Context(), sdk.GrantPermissionRequest{
						UserID: userID, MachineID: machineID, AccessType: "ssh", RemoteUsers: []string{"deploy"},
					})
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.orionbelt_access_review.web", "compliant", "false"),
					resource.TestCheckResourceAttr("data.orionbelt_access_review.web", "findings.0.rule", "grant-expiry"),
					resource.TestMatchResourceAttr("data.orionbelt_access_review.web", "findings.0.controls", regexp.MustCompile(`SOC 2 CC6\.2`)),
				),
			},
		},
	})
}
