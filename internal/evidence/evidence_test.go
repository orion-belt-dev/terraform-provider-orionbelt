package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 2, 22, 0, 0, 0, time.UTC)

// testdata/plan.json is a real `terraform show -json` plan from a lab
// gateway: SOC 2 profile, one managed grant, and one grant without expiry
// added through the API behind Terraform's back.
func readPlan(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildFromRealPlan(t *testing.T) {
	r, err := Build(readPlan(t), Source{Repository: "acme/infra", Commit: "abc123"}, now)
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Plan.SHA256) != 64 || r.Plan.TerraformVersion == "" {
		t.Errorf("plan info = %+v", r.Plan)
	}
	if !slices.Equal(r.Frameworks, []string{"soc2"}) || len(r.Guardrails) != 5 {
		t.Errorf("frameworks = %v, guardrails = %d", r.Frameworks, len(r.Guardrails))
	}
	if len(r.Drift) != 1 || r.Drift[0].Address != "orionbelt_machine_access.web" {
		t.Errorf("drift = %+v", r.Drift)
	}
	if len(r.Pending) != 1 || !slices.Equal(r.Pending[0].Actions, []string{"update"}) {
		t.Errorf("pending = %+v", r.Pending)
	}

	if len(r.AccessReviews) != 1 {
		t.Fatalf("access reviews = %+v", r.AccessReviews)
	}
	review := r.AccessReviews[0]
	if review.Status != "evaluated" || review.Compliant || len(review.Findings) != 1 || review.Findings[0].Rule != "grant-expiry" {
		t.Errorf("review = %+v", review)
	}

	status := map[string]string{}
	for _, c := range r.Controls {
		status[c.Control] = c.Status
	}
	if status["SOC 2 CC6.3"] != StatusFinding || status["SOC 2 CC7.2"] != StatusEnforced {
		t.Errorf("control status = %v", status)
	}

	if r.Compliant || len(r.Reasons) != 2 {
		t.Errorf("compliant = %v, reasons = %v", r.Compliant, r.Reasons)
	}
}

func TestReportCarriesNoAttributeValues(t *testing.T) {
	r, err := Build(readPlan(t), Source{}, now)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"ssh-ed25519", "10.0.0.9", "localhost:8080"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("report contains %q from the plan", leak)
		}
	}
}

func TestCompliantPlan(t *testing.T) {
	plan := `{
  "terraform_version": "1.15.9",
  "prior_state": {"values": {"root_module": {
    "resources": [
      {"address": "data.orionbelt_compliance_profile.this", "mode": "data", "type": "orionbelt_compliance_profile",
       "values": {"frameworks": ["pci-dss-4"], "rules": [{"rule": "grant-expiry", "setting": "x", "controls": ["PCI DSS 4.0 7.2.4"]}]}}
    ],
    "child_modules": [{"resources": [
      {"address": "module.gw.data.orionbelt_access_review.all", "mode": "data", "type": "orionbelt_access_review",
       "values": {"compliant": true, "entries": [], "findings": []}}
    ]}]
  }}},
  "resource_drift": [
    {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "change": {"actions": ["update"]}}
  ]
}`
	r, err := Build([]byte(plan), Source{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Compliant {
		t.Fatalf("want compliant (drift outside orionbelt is reported, not failed): %v", r.Reasons)
	}
	if len(r.Drift) != 1 || len(r.Controls) != 1 || r.Controls[0].Status != StatusEnforced {
		t.Errorf("report = %+v", r)
	}
}

func TestDeferredReviewIsNotCompliant(t *testing.T) {
	plan := `{
  "terraform_version": "1.15.9",
  "prior_state": {"values": {"root_module": {"resources": [
    {"address": "data.orionbelt_compliance_profile.this", "mode": "data", "type": "orionbelt_compliance_profile",
     "values": {"frameworks": ["soc2"], "rules": []}}
  ]}}},
  "resource_changes": [
    {"address": "data.orionbelt_access_review.all", "mode": "data", "type": "orionbelt_access_review", "change": {"actions": ["read"]}}
  ]
}`
	r, err := Build([]byte(plan), Source{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Compliant || r.AccessReviews[0].Status != "deferred" || len(r.Pending) != 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestBuildErrors(t *testing.T) {
	cases := map[string]string{
		"not json":   `{`,
		"not a plan": `{"format_version": "1.0"}`,
		"no profile": `{"terraform_version": "1.15.9"}`,
	}
	for name, plan := range cases {
		if _, err := Build([]byte(plan), Source{}, now); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestDriftInsideForEachModuleCounts(t *testing.T) {
	plan := `{
  "terraform_version": "1.15.9",
  "prior_state": {"values": {"root_module": {"resources": [
    {"address": "data.orionbelt_compliance_profile.this", "mode": "data", "type": "orionbelt_compliance_profile",
     "values": {"frameworks": ["soc2"], "rules": []}},
    {"address": "data.orionbelt_access_review.all", "mode": "data", "type": "orionbelt_access_review",
     "values": {"compliant": true, "entries": [], "findings": []}}
  ]}}},
  "resource_drift": [
    {"address": "module.site[\"eu.west\"].orionbelt_machine_access.web", "mode": "managed", "type": "orionbelt_machine_access",
     "change": {"actions": ["update"]}}
  ]
}`
	r, err := Build([]byte(plan), Source{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Compliant {
		t.Fatal("drift on an orionbelt resource inside a for_each module must fail")
	}
}

func TestProfileMustBeReadAtPlanAndUnique(t *testing.T) {
	profile := `{"address": "%s", "mode": "data", "type": "orionbelt_compliance_profile", "values": {"frameworks": ["soc2"], "rules": []}}`
	cases := map[string]string{
		"deferred": `{"terraform_version": "1.15.9",
  "prior_state": {"values": {"root_module": {"resources": [` + fmt.Sprintf(profile, "data.orionbelt_compliance_profile.this") + `]}}},
  "resource_changes": [{"address": "data.orionbelt_compliance_profile.this", "mode": "data", "type": "orionbelt_compliance_profile", "change": {"actions": ["read"]}}]}`,
		"two": `{"terraform_version": "1.15.9",
  "prior_state": {"values": {"root_module": {"resources": [` + fmt.Sprintf(profile, "data.orionbelt_compliance_profile.a") + `,` + fmt.Sprintf(profile, "data.orionbelt_compliance_profile.b") + `]}}}}`,
	}
	for name, plan := range cases {
		if _, err := Build([]byte(plan), Source{}, now); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
