package compliance

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Violation is one broken rule.
type Violation struct {
	Rule     string
	Field    string
	Message  string
	Controls string
}

func (v Violation) Error() string {
	return fmt.Sprintf("%s (%s)", v.Message, v.Controls)
}

// Grant is the part of a permission the rules look at. ExpiresAt is nil
// when the grant never expires.
type Grant struct {
	AccessType  string
	RemoteUsers []string
	ExpiresAt   *time.Time
}

// User is the part of a user the rules look at.
type User struct {
	Username string
	Email    string
}

// Agent is the part of an agent the rules look at. HostCAKnown is false
// while the gateway has not been asked whether it runs an SSH CA.
type Agent struct {
	ArchiveOnDestroy bool
	HostCAKnown      bool
	HostCAPublicKey  string
	GatewayHostKey   string
}

// RiskPolicy is the part of the risk policy the rules look at.
type RiskPolicy struct {
	AutoApproveEnabled     bool
	AutoApproveMaxDuration time.Duration
	AutoApproveRequireMFA  bool
	AutoApproveRemoteUsers []string
	EscalateEnabled        bool
	EscalateWithoutMFA     bool
}

// sharedAccountNames are generic names that cannot identify one person.
var sharedAccountNames = []string{
	"admin", "administrator", "root", "shared", "team", "ops", "devops",
	"test", "guest", "user", "support", "service", "default",
}

func (p Profile) violation(rule, field, format string, args ...any) Violation {
	return Violation{
		Rule:     rule,
		Field:    field,
		Message:  fmt.Sprintf(format, args...),
		Controls: ControlsText(rule, p.Frameworks),
	}
}

// CheckGrant checks one permission grant at time now.
func (p Profile) CheckGrant(g Grant, now time.Time) []Violation {
	var out []Violation

	if g.ExpiresAt == nil {
		if p.RequireGrantExpiry || p.MaxGrantDuration > 0 {
			out = append(out, p.violation(RuleGrantExpiry, "expires_at",
				"access grants must expire; set expires_at"))
		}
	} else if p.MaxGrantDuration > 0 {
		limit := now.Add(p.MaxGrantDuration)
		if g.ExpiresAt.After(limit) {
			out = append(out, p.violation(RuleGrantDuration, "expires_at",
				"expires_at %s is more than %s from now; the latest allowed is %s",
				g.ExpiresAt.UTC().Format(time.RFC3339), formatDuration(p.MaxGrantDuration),
				limit.UTC().Format(time.RFC3339)))
		}
	}

	for _, u := range g.RemoteUsers {
		if slices.Contains(p.DeniedRemoteUsers, u) {
			out = append(out, p.violation(RuleDeniedRemoteUser, "remote_users",
				"remote user %q is not allowed; grant a named, least-privileged account", u))
		}
	}
	return out
}

// CheckUser checks one user account.
func (p Profile) CheckUser(u User) []Violation {
	var out []Violation
	if p.DenySharedAccounts && slices.Contains(sharedAccountNames, strings.ToLower(u.Username)) {
		out = append(out, p.violation(RuleSharedAccount, "username",
			"username %q looks like a shared account; accounts must belong to one person", u.Username))
	}
	if p.RequireUserEmail && strings.TrimSpace(u.Email) == "" {
		out = append(out, p.violation(RuleUserEmail, "email",
			"users must have an email address that identifies their owner"))
	}
	return out
}

// CheckAgent checks one agent registration.
func (p Profile) CheckAgent(a Agent) []Violation {
	var out []Violation
	if p.RequireArchive && !a.ArchiveOnDestroy {
		out = append(out, p.violation(RuleArchive, "archive_on_destroy",
			"destroying this agent would delete its session recordings; set archive_on_destroy = true"))
	}
	if p.RequireHostCA && a.HostCAKnown && a.HostCAPublicKey == "" && a.GatewayHostKey == "" {
		out = append(out, p.violation(RuleHostCA, "gateway_host_key",
			"the agent cannot verify the gateway: enable ssh_ca on the gateway or pin gateway_host_key"))
	}
	return out
}

// CheckRiskPolicy checks the gateway's access request risk policy.
func (p Profile) CheckRiskPolicy(r RiskPolicy) []Violation {
	var out []Violation
	if p.MaxAutoApprovalTime > 0 && r.AutoApproveEnabled && r.AutoApproveMaxDuration > p.MaxAutoApprovalTime {
		out = append(out, p.violation(RuleAutoApproval, "auto_approve.max_duration",
			"auto-approved access may last at most %s", formatDuration(p.MaxAutoApprovalTime)))
	}
	escalatesWithoutMFA := r.EscalateEnabled && r.EscalateWithoutMFA
	if p.RequireMFAEscalate && !escalatesWithoutMFA {
		out = append(out, p.violation(RuleMFAEscalate, "escalate.without_mfa",
			"requests from users without MFA must be escalated; set escalate.enabled and escalate.without_mfa"))
	}
	if p.RequireMFAEscalate && r.AutoApproveEnabled && !r.AutoApproveRequireMFA {
		out = append(out, p.violation(RuleMFAEscalate, "auto_approve.require_mfa",
			"auto-approval must require MFA"))
	}
	if r.AutoApproveEnabled && len(p.DeniedRemoteUsers) > 0 {
		if len(r.AutoApproveRemoteUsers) == 0 {
			out = append(out, p.violation(RuleDeniedRemoteUser, "auto_approve.remote_users",
				"auto-approval without a remote_users list could approve %v; list the accounts it may approve", p.DeniedRemoteUsers))
		}
		for _, u := range r.AutoApproveRemoteUsers {
			if slices.Contains(p.DeniedRemoteUsers, u) {
				out = append(out, p.violation(RuleDeniedRemoteUser, "auto_approve.remote_users",
					"auto-approval may not approve remote user %q", u))
			}
		}
	}
	return out
}

func formatDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}
