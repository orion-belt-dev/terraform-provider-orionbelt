package compliance

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Framework names accepted in the provider's compliance block.
const (
	SOC2     = "soc2"
	ISO27001 = "iso27001"
	PCIDSS4  = "pci-dss-4"
)

// Profile is the set of rules in force. Several frameworks merge into one
// profile; the strictest setting always wins.
type Profile struct {
	Frameworks []string

	RequireGrantExpiry  bool
	MaxGrantDuration    time.Duration
	DeniedRemoteUsers   []string
	DenySharedAccounts  bool
	RequireUserEmail    bool
	RequireArchive      bool
	RequireHostCA       bool
	RequireMFAEscalate  bool
	MaxAutoApprovalTime time.Duration
}

// Overrides are user-set rules layered on top of the frameworks. They can
// only make the profile stricter.
type Overrides struct {
	MaxGrantDuration  time.Duration
	DeniedRemoteUsers []string
}

func soc2() Profile {
	return Profile{
		RequireGrantExpiry: true,
		MaxGrantDuration:   90 * 24 * time.Hour,
		DenySharedAccounts: true,
		RequireUserEmail:   true,
		RequireArchive:     true,
	}
}

func iso27001() Profile {
	return Profile{
		RequireGrantExpiry: true,
		MaxGrantDuration:   90 * 24 * time.Hour,
		DenySharedAccounts: true,
		RequireUserEmail:   true,
		RequireArchive:     true,
		RequireHostCA:      true,
	}
}

func pciDSS4() Profile {
	return Profile{
		RequireGrantExpiry:  true,
		MaxGrantDuration:    30 * 24 * time.Hour,
		DeniedRemoteUsers:   []string{"root"},
		DenySharedAccounts:  true,
		RequireUserEmail:    true,
		RequireArchive:      true,
		RequireHostCA:       true,
		RequireMFAEscalate:  true,
		MaxAutoApprovalTime: 8 * time.Hour,
	}
}

// KnownFrameworks lists the framework names in a stable order.
func KnownFrameworks() []string {
	return []string{ISO27001, PCIDSS4, SOC2}
}

// NewProfile builds the merged profile for the given frameworks.
func NewProfile(frameworks []string, overrides Overrides) (Profile, error) {
	merged := Profile{}
	for _, name := range frameworks {
		var p Profile
		switch name {
		case SOC2:
			p = soc2()
		case ISO27001:
			p = iso27001()
		case PCIDSS4:
			p = pciDSS4()
		default:
			return Profile{}, fmt.Errorf("unknown compliance framework %q (known: %v)", name, KnownFrameworks())
		}
		merged = merge(merged, p)
		if !slices.Contains(merged.Frameworks, name) {
			merged.Frameworks = append(merged.Frameworks, name)
		}
	}
	sort.Strings(merged.Frameworks)

	merged = merge(merged, Profile{
		MaxGrantDuration:  overrides.MaxGrantDuration,
		DeniedRemoteUsers: overrides.DeniedRemoteUsers,
	})
	return merged, nil
}

// Enabled reports whether any rule is in force.
func (p Profile) Enabled() bool {
	return len(p.Frameworks) > 0 || p.MaxGrantDuration > 0 || len(p.DeniedRemoteUsers) > 0
}

func merge(a, b Profile) Profile {
	out := a
	out.RequireGrantExpiry = a.RequireGrantExpiry || b.RequireGrantExpiry
	out.MaxGrantDuration = stricterDuration(a.MaxGrantDuration, b.MaxGrantDuration)
	out.DenySharedAccounts = a.DenySharedAccounts || b.DenySharedAccounts
	out.RequireUserEmail = a.RequireUserEmail || b.RequireUserEmail
	out.RequireArchive = a.RequireArchive || b.RequireArchive
	out.RequireHostCA = a.RequireHostCA || b.RequireHostCA
	out.RequireMFAEscalate = a.RequireMFAEscalate || b.RequireMFAEscalate
	out.MaxAutoApprovalTime = stricterDuration(a.MaxAutoApprovalTime, b.MaxAutoApprovalTime)

	out.DeniedRemoteUsers = slices.Clone(a.DeniedRemoteUsers)
	for _, u := range b.DeniedRemoteUsers {
		if !slices.Contains(out.DeniedRemoteUsers, u) {
			out.DeniedRemoteUsers = append(out.DeniedRemoteUsers, u)
		}
	}
	sort.Strings(out.DeniedRemoteUsers)
	return out
}

// stricterDuration returns the smaller non-zero limit. Zero means no limit.
func stricterDuration(a, b time.Duration) time.Duration {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}

// RuleSetting is one rule in force and what it requires.
type RuleSetting struct {
	Rule     string
	Setting  string
	Controls []string
}

// Rules lists the rules the profile enforces, for evidence exports.
func (p Profile) Rules() []RuleSetting {
	var out []RuleSetting
	add := func(rule, setting string) {
		out = append(out, RuleSetting{Rule: rule, Setting: setting, Controls: Controls(rule, p.Frameworks)})
	}
	if p.RequireGrantExpiry {
		add(RuleGrantExpiry, "every grant sets expires_at")
	}
	if p.MaxGrantDuration > 0 {
		add(RuleGrantDuration, "grants expire within "+formatDuration(p.MaxGrantDuration))
	}
	if len(p.DeniedRemoteUsers) > 0 {
		add(RuleDeniedRemoteUser, "no grant names "+strings.Join(p.DeniedRemoteUsers, ", "))
	}
	if p.DenySharedAccounts {
		add(RuleSharedAccount, "no generic or shared usernames")
	}
	if p.RequireUserEmail {
		add(RuleUserEmail, "every user has an email address")
	}
	if p.RequireArchive {
		add(RuleArchive, "agents are archived, never deleted, so recordings are kept")
	}
	if p.RequireHostCA {
		add(RuleHostCA, "agents verify the gateway by host CA or pinned key")
	}
	if p.RequireMFAEscalate {
		add(RuleMFAEscalate, "requests without MFA escalate; auto-approval requires MFA")
	}
	if p.MaxAutoApprovalTime > 0 {
		add(RuleAutoApproval, "auto-approved access lasts at most "+formatDuration(p.MaxAutoApprovalTime))
	}
	return out
}
