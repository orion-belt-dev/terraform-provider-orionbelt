package compliance

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func mustProfile(t *testing.T, frameworks []string, o Overrides) Profile {
	t.Helper()
	p, err := NewProfile(frameworks, o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func at(d time.Duration) *time.Time {
	t := now.Add(d)
	return &t
}

func rules(vs []Violation) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.Rule)
	}
	return out
}

func TestNewProfileUnknownFramework(t *testing.T) {
	_, err := NewProfile([]string{"hipaa"}, Overrides{})
	if err == nil || !strings.Contains(err.Error(), "hipaa") {
		t.Fatalf("want unknown framework error, got %v", err)
	}
}

func TestNewProfileMergesStrictest(t *testing.T) {
	p := mustProfile(t, []string{SOC2, PCIDSS4}, Overrides{
		MaxGrantDuration:  60 * 24 * time.Hour,
		DeniedRemoteUsers: []string{"postgres"},
	})
	if p.MaxGrantDuration != 30*24*time.Hour {
		t.Errorf("max grant duration = %s, want PCI's 30d", p.MaxGrantDuration)
	}
	if got := strings.Join(p.DeniedRemoteUsers, ","); got != "postgres,root" {
		t.Errorf("denied users = %s", got)
	}
	if got := strings.Join(p.Frameworks, ","); got != "pci-dss-4,soc2" {
		t.Errorf("frameworks = %s", got)
	}
}

func TestOverrideTightensFramework(t *testing.T) {
	p := mustProfile(t, []string{SOC2}, Overrides{MaxGrantDuration: 8 * time.Hour})
	if p.MaxGrantDuration != 8*time.Hour {
		t.Fatalf("max grant duration = %s", p.MaxGrantDuration)
	}
}

func TestEmptyProfileAllowsEverything(t *testing.T) {
	p := mustProfile(t, nil, Overrides{})
	if p.Enabled() {
		t.Fatal("empty profile should be disabled")
	}
	if vs := p.CheckGrant(Grant{RemoteUsers: []string{"root"}}, now); len(vs) != 0 {
		t.Fatalf("got %v", vs)
	}
	if vs := p.CheckAgent(Agent{}); len(vs) != 0 {
		t.Fatalf("got %v", vs)
	}
}

func TestCheckGrant(t *testing.T) {
	p := mustProfile(t, []string{PCIDSS4}, Overrides{})
	tests := []struct {
		name  string
		grant Grant
		want  []string
	}{
		{"compliant", Grant{RemoteUsers: []string{"deploy"}, ExpiresAt: at(24 * time.Hour)}, nil},
		{"no expiry", Grant{RemoteUsers: []string{"deploy"}}, []string{RuleGrantExpiry}},
		{"too long", Grant{RemoteUsers: []string{"deploy"}, ExpiresAt: at(31 * 24 * time.Hour)}, []string{RuleGrantDuration}},
		{"exactly at limit", Grant{RemoteUsers: []string{"deploy"}, ExpiresAt: at(30 * 24 * time.Hour)}, nil},
		{"root", Grant{RemoteUsers: []string{"deploy", "root"}, ExpiresAt: at(time.Hour)}, []string{RuleDeniedRemoteUser}},
		{"everything wrong", Grant{RemoteUsers: []string{"root"}}, []string{RuleGrantExpiry, RuleDeniedRemoteUser}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rules(p.CheckGrant(tt.grant, now))
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestViolationCitesControls(t *testing.T) {
	p := mustProfile(t, []string{SOC2, PCIDSS4}, Overrides{})
	vs := p.CheckGrant(Grant{RemoteUsers: []string{"root"}, ExpiresAt: at(time.Hour)}, now)
	if len(vs) != 1 {
		t.Fatalf("got %v", vs)
	}
	if !strings.Contains(vs[0].Error(), "PCI DSS 4.0 7.2.2") {
		t.Fatalf("message does not cite the control: %s", vs[0].Error())
	}
}

func TestOverrideOnlyRuleCitesOverride(t *testing.T) {
	p := mustProfile(t, nil, Overrides{DeniedRemoteUsers: []string{"root"}})
	vs := p.CheckGrant(Grant{RemoteUsers: []string{"root"}}, now)
	if len(vs) != 1 || vs[0].Controls != "provider compliance override" {
		t.Fatalf("got %v", vs)
	}
}

func TestCheckUser(t *testing.T) {
	p := mustProfile(t, []string{SOC2}, Overrides{})
	if vs := p.CheckUser(User{Username: "jane", Email: "jane@example.com"}); len(vs) != 0 {
		t.Fatalf("got %v", vs)
	}
	got := rules(p.CheckUser(User{Username: "Admin"}))
	if strings.Join(got, ",") != RuleSharedAccount+","+RuleUserEmail {
		t.Fatalf("got %v", got)
	}
}

func TestCheckAgent(t *testing.T) {
	p := mustProfile(t, []string{ISO27001}, Overrides{})
	if vs := p.CheckAgent(Agent{ArchiveOnDestroy: true, HostCAKnown: true, HostCAPublicKey: "ssh-ed25519 AAAA"}); len(vs) != 0 {
		t.Fatalf("got %v", vs)
	}
	got := rules(p.CheckAgent(Agent{ArchiveOnDestroy: false, HostCAKnown: true}))
	if strings.Join(got, ",") != RuleArchive+","+RuleHostCA {
		t.Fatalf("got %v", got)
	}
	if vs := p.CheckAgent(Agent{ArchiveOnDestroy: true, HostCAKnown: true, GatewayHostKey: "ssh-ed25519 AAAA"}); len(vs) != 0 {
		t.Fatalf("a pinned host key should satisfy the rule: %v", vs)
	}
	if vs := p.CheckAgent(Agent{ArchiveOnDestroy: true, HostCAKnown: false}); len(vs) != 0 {
		t.Fatalf("unknown CA must not fail at plan time: %v", vs)
	}
}

func TestCheckRiskPolicy(t *testing.T) {
	p := mustProfile(t, []string{PCIDSS4}, Overrides{})
	ok := RiskPolicy{
		AutoApproveEnabled:     true,
		AutoApproveMaxDuration: time.Hour,
		AutoApproveRequireMFA:  true,
		AutoApproveRemoteUsers: []string{"deploy"},
		EscalateEnabled:        true,
		EscalateWithoutMFA:     true,
	}
	if vs := p.CheckRiskPolicy(ok); len(vs) != 0 {
		t.Fatalf("got %v", vs)
	}
	bad := RiskPolicy{AutoApproveEnabled: true, AutoApproveMaxDuration: 24 * time.Hour}
	got := rules(p.CheckRiskPolicy(bad))
	want := []string{RuleAutoApproval, RuleMFAEscalate, RuleMFAEscalate, RuleDeniedRemoteUser}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}

	root := ok
	root.AutoApproveRemoteUsers = []string{"root"}
	if got := rules(p.CheckRiskPolicy(root)); strings.Join(got, ",") != RuleDeniedRemoteUser {
		t.Fatalf("got %v", got)
	}
}

func TestMaxDurationOverrideAloneRequiresExpiry(t *testing.T) {
	p := mustProfile(t, nil, Overrides{MaxGrantDuration: 8 * time.Hour})
	got := rules(p.CheckGrant(Grant{RemoteUsers: []string{"deploy"}}, now))
	if strings.Join(got, ",") != RuleGrantExpiry {
		t.Fatalf("a grant that never expires must break a max duration: got %v", got)
	}
}
