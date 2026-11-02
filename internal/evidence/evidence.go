// Package evidence turns a Terraform plan into a compliance evidence report.
// It reads only what it needs from `terraform show -json` output, so the
// report never carries the plan's attribute values or secrets.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const Schema = "https://orion-belt.dev/evidence/v1"

const (
	StatusEnforced = "enforced"
	StatusFinding  = "finding"
)

// Source identifies the run that produced the plan.
type Source struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	RunURL     string `json:"run_url"`
}

type Report struct {
	Schema        string         `json:"schema"`
	GeneratedAt   string         `json:"generated_at"`
	Source        Source         `json:"source"`
	Plan          PlanInfo       `json:"plan"`
	Frameworks    []string       `json:"frameworks"`
	Guardrails    []Guardrail    `json:"guardrails"`
	Controls      []Control      `json:"controls"`
	AccessReviews []AccessReview `json:"access_reviews"`
	Drift         []Change       `json:"drift"`
	Pending       []Change       `json:"pending_changes"`
	Compliant     bool           `json:"compliant"`
	Reasons       []string       `json:"reasons"`
}

type PlanInfo struct {
	SHA256           string `json:"sha256"`
	TerraformVersion string `json:"terraform_version"`
	Timestamp        string `json:"timestamp"`
}

// Guardrail is a rule the provider enforces at plan and apply time.
type Guardrail struct {
	Rule     string   `json:"rule"`
	Setting  string   `json:"setting"`
	Controls []string `json:"controls"`
}

type Control struct {
	Control string   `json:"control"`
	Rules   []string `json:"rules"`
	Status  string   `json:"status"`
}

type AccessReview struct {
	Address     string        `json:"address"`
	Status      string        `json:"status"`
	MachineIDs  []string      `json:"machine_ids"`
	GeneratedAt string        `json:"generated_at,omitempty"`
	Compliant   bool          `json:"compliant"`
	Entries     []AccessEntry `json:"entries"`
	Findings    []Finding     `json:"findings"`
}

type AccessEntry struct {
	Username    string   `json:"username"`
	MachineName string   `json:"machine_name"`
	AccessType  string   `json:"access_type"`
	RemoteUsers []string `json:"remote_users"`
	Source      string   `json:"source"`
	ExpiresAt   *string  `json:"expires_at"`
}

type Finding struct {
	Username    string `json:"username"`
	MachineName string `json:"machine_name"`
	Rule        string `json:"rule"`
	Message     string `json:"message"`
	Controls    string `json:"controls"`
}

// Change names a resource and what Terraform would do to it, never the
// values involved.
type Change struct {
	Address string   `json:"address"`
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
}

// plan is the subset of `terraform show -json` this package reads.
type plan struct {
	TerraformVersion string           `json:"terraform_version"`
	Timestamp        string           `json:"timestamp"`
	Errored          bool             `json:"errored"`
	ResourceDrift    []resourceChange `json:"resource_drift"`
	ResourceChanges  []resourceChange `json:"resource_changes"`
	PriorState       *struct {
		Values struct {
			RootModule module `json:"root_module"`
		} `json:"values"`
	} `json:"prior_state"`
}

type module struct {
	Resources    []stateResource `json:"resources"`
	ChildModules []module        `json:"child_modules"`
}

type stateResource struct {
	Address string          `json:"address"`
	Mode    string          `json:"mode"`
	Type    string          `json:"type"`
	Values  json.RawMessage `json:"values"`
}

type resourceChange struct {
	Address string `json:"address"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Change  struct {
		Actions []string `json:"actions"`
	} `json:"change"`
}

type profileValues struct {
	Frameworks []string    `json:"frameworks"`
	Rules      []Guardrail `json:"rules"`
}

type reviewValues struct {
	MachineIDs  []string      `json:"machine_ids"`
	GeneratedAt string        `json:"generated_at"`
	Compliant   bool          `json:"compliant"`
	Entries     []AccessEntry `json:"entries"`
	Findings    []Finding     `json:"findings"`
}

// Build reads a JSON plan and produces the evidence report.
func Build(planJSON []byte, src Source, now time.Time) (Report, error) {
	var p plan
	if err := json.Unmarshal(planJSON, &p); err != nil {
		return Report{}, fmt.Errorf("read plan JSON: %w", err)
	}
	if p.TerraformVersion == "" {
		return Report{}, errors.New("not a plan: run `terraform show -json <planfile>`")
	}
	sum := sha256.Sum256(planJSON)

	r := Report{
		Schema:      Schema,
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Source:      src,
		Plan: PlanInfo{
			SHA256:           hex.EncodeToString(sum[:]),
			TerraformVersion: p.TerraformVersion,
			Timestamp:        p.Timestamp,
		},
		Frameworks:    []string{},
		Guardrails:    []Guardrail{},
		Controls:      []Control{},
		AccessReviews: []AccessReview{},
		Drift:         []Change{},
		Pending:       []Change{},
		Reasons:       []string{},
	}

	var resources []stateResource
	if p.PriorState != nil {
		resources = flatten(p.PriorState.Values.RootModule)
	}

	profiles := 0
	for _, res := range resources {
		if res.Mode != "data" {
			continue
		}
		switch res.Type {
		case "orionbelt_compliance_profile":
			profiles++
			var v profileValues
			if err := json.Unmarshal(res.Values, &v); err != nil {
				return Report{}, fmt.Errorf("%s: %w", res.Address, err)
			}
			r.Frameworks = v.Frameworks
			r.Guardrails = v.Rules
		case "orionbelt_access_review":
			var v reviewValues
			if err := json.Unmarshal(res.Values, &v); err != nil {
				return Report{}, fmt.Errorf("%s: %w", res.Address, err)
			}
			r.AccessReviews = append(r.AccessReviews, AccessReview{
				Address:     res.Address,
				Status:      "evaluated",
				MachineIDs:  nonNil(v.MachineIDs),
				GeneratedAt: v.GeneratedAt,
				Compliant:   v.Compliant,
				Entries:     nonNil(v.Entries),
				Findings:    nonNil(v.Findings),
			})
		}
	}
	for _, c := range p.ResourceChanges {
		if c.Mode == "data" && c.Type == "orionbelt_compliance_profile" {
			return Report{}, fmt.Errorf("%s is deferred to apply; remove its depends_on so the plan reads it", c.Address)
		}
	}
	if profiles == 0 {
		return Report{}, errors.New(`plan has no data "orionbelt_compliance_profile"; add one so the report can name the frameworks enforced`)
	}
	if profiles > 1 {
		return Report{}, errors.New(`plan has more than one data "orionbelt_compliance_profile"; keep one per configuration`)
	}

	for _, c := range p.ResourceChanges {
		if c.Mode == "data" && c.Type == "orionbelt_access_review" {
			r.AccessReviews = append(r.AccessReviews, AccessReview{
				Address:    c.Address,
				Status:     "deferred",
				MachineIDs: []string{},
				Entries:    []AccessEntry{},
				Findings:   []Finding{},
			})
			continue
		}
		if c.Mode == "managed" && !isNoOp(c.Change.Actions) {
			r.Pending = append(r.Pending, Change{Address: c.Address, Type: c.Type, Actions: c.Change.Actions})
		}
	}
	for _, c := range p.ResourceDrift {
		r.Drift = append(r.Drift, Change{Address: c.Address, Type: c.Type, Actions: c.Change.Actions})
	}
	sort.Slice(r.AccessReviews, func(i, j int) bool { return r.AccessReviews[i].Address < r.AccessReviews[j].Address })

	r.Controls = controls(r.Guardrails, r.AccessReviews)
	r.Reasons = reasons(p, r)
	r.Compliant = len(r.Reasons) == 0
	return r, nil
}

func flatten(m module) []stateResource {
	out := append([]stateResource{}, m.Resources...)
	for _, child := range m.ChildModules {
		out = append(out, flatten(child)...)
	}
	return out
}

func isNoOp(actions []string) bool {
	return len(actions) == 1 && (actions[0] == "no-op" || actions[0] == "read")
}

func nonNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

// controls lists each control the guardrails support. A control is a
// finding when a live access review broke one of its rules.
func controls(guardrails []Guardrail, reviews []AccessReview) []Control {
	broken := map[string]bool{}
	for _, review := range reviews {
		for _, f := range review.Findings {
			broken[f.Rule] = true
		}
	}

	byControl := map[string]*Control{}
	for _, g := range guardrails {
		for _, id := range g.Controls {
			c, ok := byControl[id]
			if !ok {
				c = &Control{Control: id, Status: StatusEnforced}
				byControl[id] = c
			}
			c.Rules = append(c.Rules, g.Rule)
			if broken[g.Rule] {
				c.Status = StatusFinding
			}
		}
	}

	out := make([]Control, 0, len(byControl))
	for _, c := range byControl {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Control < out[j].Control })
	return out
}

// reasons explains why the run is not compliant. Empty means compliant.
func reasons(p plan, r Report) []string {
	out := []string{}
	if p.Errored {
		out = append(out, "the plan errored")
	}
	if len(r.Frameworks) == 0 {
		out = append(out, "no compliance frameworks are declared")
	}
	if len(r.AccessReviews) == 0 {
		out = append(out, `no data "orionbelt_access_review" in the plan`)
	}
	for _, review := range r.AccessReviews {
		switch {
		case review.Status == "deferred":
			out = append(out, review.Address+" was deferred to apply; remove its dependency on managed resources")
		case !review.Compliant:
			out = append(out, fmt.Sprintf("%s has %d finding(s)", review.Address, len(review.Findings)))
		}
	}
	for _, c := range r.Drift {
		if strings.HasPrefix(c.Type, "orionbelt_") {
			out = append(out, c.Address+" changed outside Terraform")
		}
	}
	return out
}
