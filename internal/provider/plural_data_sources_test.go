package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
)

func TestMachinesDataSourceFilters(t *testing.T) {
	g := newFakeGateway(t)
	g.addMachineWithTags("web-2", true, map[string]string{"env": "prod", "team": "web"})
	g.addMachineWithTags("web-1", true, map[string]string{"env": "prod", "team": "web"})
	g.addMachineWithTags("web-3", false, map[string]string{"env": "prod", "team": "web"})
	g.addMachineWithTags("web-stg", true, map[string]string{"env": "staging", "team": "web"})
	g.addMachineWithTags("db-1", true, map[string]string{"env": "prod"})

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "soc2") + `
data "orionbelt_machines" "all" {}

data "orionbelt_machines" "prod_web" {
  name_prefix = "web-"
  tags        = { env = "prod" }
  active_only = true
}

data "orionbelt_machines" "none" {
  tags = { env = "prod", team = "db" }
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("data.orionbelt_machines.all", "machines.#", "5"),
				resource.TestCheckResourceAttr("data.orionbelt_machines.all", "machines.0.name", "db-1"),

				resource.TestCheckResourceAttr("data.orionbelt_machines.prod_web", "machines.#", "2"),
				resource.TestCheckResourceAttr("data.orionbelt_machines.prod_web", "machines.0.name", "web-1"),
				resource.TestCheckResourceAttr("data.orionbelt_machines.prod_web", "machines.1.name", "web-2"),
				resource.TestCheckResourceAttr("data.orionbelt_machines.prod_web", "machines.0.tags.team", "web"),
				resource.TestCheckResourceAttr("data.orionbelt_machines.prod_web", "machines.0.port", "22"),
				resource.TestCheckResourceAttr("data.orionbelt_machines.prod_web", "machines.0.is_active", "true"),
				resource.TestCheckResourceAttrSet("data.orionbelt_machines.prod_web", "machines.0.id"),

				resource.TestCheckResourceAttr("data.orionbelt_machines.none", "machines.#", "0"),
			),
		}},
	})
}

func TestUsersDataSourceFilters(t *testing.T) {
	g := newFakeGateway(t)
	g.addUser("ops-bob", "operator")
	g.addUser("ops-alice", "operator")
	g.addUser("ops-carol", "user")
	g.addUser("dev-dan", "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			Config: providerBlock(g, "soc2") + `
data "orionbelt_users" "all" {}

data "orionbelt_users" "operators" {
  username_prefix = "ops-"
  role            = "operator"
}

data "orionbelt_users" "plain" {
  role = "user"
}
`,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("data.orionbelt_users.all", "users.#", "4"),
				resource.TestCheckResourceAttr("data.orionbelt_users.all", "users.0.username", "dev-dan"),

				resource.TestCheckResourceAttr("data.orionbelt_users.operators", "users.#", "2"),
				resource.TestCheckResourceAttr("data.orionbelt_users.operators", "users.0.username", "ops-alice"),
				resource.TestCheckResourceAttr("data.orionbelt_users.operators", "users.0.email", "ops-alice@example.com"),
				resource.TestCheckResourceAttr("data.orionbelt_users.operators", "users.0.mfa_enabled", "false"),

				// An empty role on the gateway means "user".
				resource.TestCheckResourceAttr("data.orionbelt_users.plain", "users.#", "2"),
				resource.TestCheckResourceAttr("data.orionbelt_users.plain", "users.0.username", "dev-dan"),
				resource.TestCheckResourceAttr("data.orionbelt_users.plain", "users.0.role", "user"),
			),
		}},
	})
}

func TestMachineMatches(t *testing.T) {
	t.Parallel()
	m := sdk.Machine{Name: "web-1", IsActive: false, Tags: map[string]string{"env": "prod"}}
	tests := []struct {
		name       string
		prefix     string
		tags       map[string]string
		activeOnly bool
		want       bool
	}{
		{name: "no filters", want: true},
		{name: "prefix matches", prefix: "web", want: true},
		{name: "prefix differs", prefix: "db", want: false},
		{name: "tag matches", tags: map[string]string{"env": "prod"}, want: true},
		{name: "tag value differs", tags: map[string]string{"env": "dev"}, want: false},
		{name: "tag missing", tags: map[string]string{"team": "web"}, want: false},
		{name: "inactive excluded", activeOnly: true, want: false},
		{name: "empty tag value is not missing", tags: map[string]string{"env": ""}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := machineMatches(m, tt.prefix, tt.tags, tt.activeOnly); got != tt.want {
				t.Fatalf("machineMatches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWarnIfTruncated(t *testing.T) {
	t.Parallel()
	var below diag.Diagnostics
	warnIfTruncated(&below, "machine", listCap-1)
	if below.WarningsCount() != 0 {
		t.Fatalf("warned below the cap: %v", below)
	}
	var full diag.Diagnostics
	warnIfTruncated(&full, "machine", listCap)
	if full.WarningsCount() != 1 || full.HasError() {
		t.Fatalf("want one warning at the cap, got %v", full)
	}
}
