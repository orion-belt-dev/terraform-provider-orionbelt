package provider

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/list"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// terraform query and list blocks arrived in Terraform 1.14; OpenTofu does
// not have them, so these tests run only against Terraform 1.14 or later.
var queryVersionChecks = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_14_0),
}

func TestUserListQuery(t *testing.T) {
	g := newFakeGateway(t)
	aliceID := g.addUser("ops-alice", "operator")
	bobID := g.addUser("ops-bob", "operator")
	g.addUser("ops-carol", "user")
	g.addUser("dev-dan", "")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks:   queryVersionChecks,
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: providerBlock(g, "soc2")},
			{
				Query: true,
				// The query reuses the provider configuration from step 1.
				Config: `
list "orionbelt_user" "operators" {
  provider         = orionbelt
  include_resource = true

  config {
    username_prefix = "ops-"
    role            = "operator"
  }
}

list "orionbelt_user" "first" {
  provider = orionbelt
  limit    = 1

  config {}
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectLength("orionbelt_user.operators", 2),
					querycheck.ExpectIdentity("orionbelt_user.operators", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(aliceID),
					}),
					querycheck.ExpectIdentity("orionbelt_user.operators", map[string]knownvalue.Check{
						"id": knownvalue.StringExact(bobID),
					}),
					querycheck.ExpectResourceDisplayName("orionbelt_user.operators",
						queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"id": knownvalue.StringExact(aliceID)}),
						knownvalue.StringExact("ops-alice")),
					querycheck.ExpectResourceKnownValues("orionbelt_user.operators",
						queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"id": knownvalue.StringExact(aliceID)}),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("username"), KnownValue: knownvalue.StringExact("ops-alice")},
							{Path: tfjsonpath.New("email"), KnownValue: knownvalue.StringExact("ops-alice@example.com")},
							{Path: tfjsonpath.New("role"), KnownValue: knownvalue.StringExact("operator")},
						}),

					querycheck.ExpectLength("orionbelt_user.first", 1),
				},
			},
		},
	})
}

func TestMachineAccessListQuery(t *testing.T) {
	g := newFakeGateway(t)
	web1 := g.addMachineWithTags("web-1", true, map[string]string{"env": "prod"})
	web2 := g.addMachineWithTags("web-2", true, map[string]string{"env": "prod"})
	g.addMachineWithTags("web-stg", true, map[string]string{"env": "staging"})
	g.addMachineWithTags("db-1", true, map[string]string{"env": "prod"})
	jane := g.addUser("jane", "user")
	g.addGrant(jane, web1, "ssh", "deploy")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks:   queryVersionChecks,
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{Config: providerBlock(g, "soc2")},
			{
				Query: true,
				// The query reuses the provider configuration from step 1.
				Config: `
list "orionbelt_machine_access" "prod_web" {
  provider         = orionbelt
  include_resource = true

  config {
    name_prefix = "web-"
    tags        = { env = "prod" }
  }
}
`,
				QueryResultChecks: []querycheck.QueryResultCheck{
					querycheck.ExpectLength("orionbelt_machine_access.prod_web", 2),
					querycheck.ExpectIdentity("orionbelt_machine_access.prod_web", map[string]knownvalue.Check{
						"machine_id": knownvalue.StringExact(web2),
					}),
					querycheck.ExpectResourceDisplayName("orionbelt_machine_access.prod_web",
						queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"machine_id": knownvalue.StringExact(web1)}),
						knownvalue.StringExact("web-1")),
					querycheck.ExpectResourceKnownValues("orionbelt_machine_access.prod_web",
						queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"machine_id": knownvalue.StringExact(web1)}),
						[]querycheck.KnownValueCheck{
							{Path: tfjsonpath.New("machine_id"), KnownValue: knownvalue.StringExact(web1)},
							{Path: tfjsonpath.New("grant"), KnownValue: knownvalue.ListExact([]knownvalue.Check{
								knownvalue.ObjectPartial(map[string]knownvalue.Check{
									"user_id":      knownvalue.StringExact(jane),
									"access_type":  knownvalue.StringExact("ssh"),
									"remote_users": knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("deploy")}),
								}),
							})},
						}),
				},
			},
		},
	})
}

func TestImportByIdentity(t *testing.T) {
	g := newFakeGateway(t)
	machineID := g.addMachine("web-1")

	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_12_0),
		},
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: providerBlock(g, "soc2") + `
resource "orionbelt_user" "jane" {
  username = "jane"
  email    = "jane@example.com"
}

resource "orionbelt_machine_access" "web" {
  machine_id = "` + machineID + `"

  grant {
    user_id      = orionbelt_user.jane.id
    access_type  = "ssh"
    remote_users = ["deploy"]
    expires_at   = "` + future(24*time.Hour) + `"
  }
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectIdentity("orionbelt_user.jane", map[string]knownvalue.Check{
						"id": knownvalue.NotNull(),
					}),
					statecheck.ExpectIdentity("orionbelt_machine_access.web", map[string]knownvalue.Check{
						"machine_id": knownvalue.StringExact(machineID),
					}),
				},
			},
			{
				ResourceName:    "orionbelt_user.jane",
				ImportState:     true,
				ImportStateKind: resource.ImportBlockWithResourceIdentity,
			},
			{
				ResourceName:    "orionbelt_machine_access.web",
				ImportState:     true,
				ImportStateKind: resource.ImportBlockWithResourceIdentity,
			},
		},
	})
}

func TestListQueryReportsGatewayErrors(t *testing.T) {
	g := newFakeGateway(t)
	g.failLists = true

	for _, typ := range []string{"orionbelt_user", "orionbelt_machine_access"} {
		t.Run(typ, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				TerraformVersionChecks:   queryVersionChecks,
				ProtoV6ProviderFactories: testProviders,
				Steps: []resource.TestStep{
					{Config: providerBlock(g, "soc2")},
					{
						Query: true,
						Config: `
list "` + typ + `" "all" {
  provider = orionbelt
  config {}
}
`,
						ExpectError: regexp.MustCompile(`Cannot list (users|machines)`),
					},
				},
			})
		})
	}
}

func TestListWithoutClientReportsError(t *testing.T) {
	t.Parallel()
	for name, lr := range map[string]list.ListResource{
		"user":           newUserListResource(),
		"machine_access": newMachineAccessListResource(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stream list.ListResultsStream
			lr.List(context.Background(), list.ListRequest{}, &stream)
			var results []list.ListResult
			for r := range stream.Results {
				results = append(results, r)
			}
			if len(results) != 1 || !results[0].Diagnostics.HasError() {
				t.Fatalf("want one result carrying an error, got %+v", results)
			}
			if got := results[0].Diagnostics.Errors()[0].Summary(); got != "Provider not configured" {
				t.Fatalf("summary = %q", got)
			}
		})
	}
}
