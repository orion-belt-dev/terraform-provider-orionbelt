package compliance

import "strings"

// Rule identifiers. Each one maps to the controls it supports.
const (
	RuleGrantExpiry      = "grant-expiry"
	RuleGrantDuration    = "grant-max-duration"
	RuleDeniedRemoteUser = "denied-remote-user"
	RuleSharedAccount    = "no-shared-accounts"
	RuleUserEmail        = "user-email"
	RuleArchive          = "retain-evidence"
	RuleHostCA           = "host-ca"
	RuleMFAEscalate      = "mfa-escalation"
	RuleAutoApproval     = "auto-approval-duration"
)

// controls maps each rule to the framework controls it supports.
var controls = map[string]map[string][]string{
	RuleGrantExpiry: {
		SOC2:     {"CC6.2", "CC6.3"},
		ISO27001: {"A.5.18"},
		PCIDSS4:  {"7.2.4"},
	},
	RuleGrantDuration: {
		SOC2:     {"CC6.2"},
		ISO27001: {"A.5.18"},
		PCIDSS4:  {"7.2.4"},
	},
	RuleDeniedRemoteUser: {
		PCIDSS4: {"7.2.2", "8.6.1"},
	},
	RuleSharedAccount: {
		SOC2:     {"CC6.1"},
		ISO27001: {"A.5.16"},
		PCIDSS4:  {"8.2.1", "8.2.2"},
	},
	RuleUserEmail: {
		SOC2:     {"CC6.1"},
		ISO27001: {"A.5.16"},
		PCIDSS4:  {"8.2.1"},
	},
	RuleArchive: {
		SOC2:     {"CC7.2"},
		ISO27001: {"A.8.15"},
		PCIDSS4:  {"10.5.1"},
	},
	RuleHostCA: {
		ISO27001: {"A.8.20"},
		PCIDSS4:  {"4.2.1"},
	},
	RuleMFAEscalate: {
		PCIDSS4: {"8.4.2"},
	},
	RuleAutoApproval: {
		PCIDSS4: {"7.2.5"},
	},
}

var frameworkTitles = map[string]string{
	SOC2:     "SOC 2",
	ISO27001: "ISO/IEC 27001:2022",
	PCIDSS4:  "PCI DSS 4.0",
}

// Controls returns the controls a rule supports for the given frameworks,
// formatted like "PCI DSS 4.0 7.2.2". Rules set only through overrides
// return nil.
func Controls(rule string, frameworks []string) []string {
	var out []string
	for _, fw := range frameworks {
		for _, id := range controls[rule][fw] {
			out = append(out, frameworkTitles[fw]+" "+id)
		}
	}
	return out
}

// ControlsText is Controls joined for an error message.
func ControlsText(rule string, frameworks []string) string {
	c := Controls(rule, frameworks)
	if len(c) == 0 {
		return "provider compliance override"
	}
	return strings.Join(c, ", ")
}
