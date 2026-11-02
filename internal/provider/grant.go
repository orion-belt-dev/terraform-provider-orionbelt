package provider

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/compliance"
)

var accessTypes = []string{"ssh", "scp", "both", "rdp", "vnc", "k8s"}

// accessTypesNeedingUsers are checked against a specific remote account, so
// a grant without one could never be used. The server rejects it too.
var accessTypesNeedingUsers = []string{"ssh", "scp", "both"}

// checkGrant validates one planned grant: expires_at must parse and lie in
// the future, and the grant must satisfy the compliance profile. Unknown
// values are skipped; they are checked again at apply time.
func checkGrant(ctx context.Context, diags *diag.Diagnostics, at path.Path, profile compliance.Profile, accessType types.String, remoteUsers types.Set, expiresAt types.String, now time.Time) {
	if expiresAt.IsUnknown() || accessType.IsUnknown() || setHasUnknown(remoteUsers) {
		return
	}
	expiry, err := parseExpiry(expiresAt)
	if err != nil {
		diags.AddAttributeError(at.AtName("expires_at"), "Invalid expires_at", err.Error())
		return
	}
	if expiry != nil && !expiry.After(now) {
		diags.AddAttributeError(at.AtName("expires_at"), "Grant already expired",
			"expires_at "+expiresAt.ValueString()+" is in the past. Renew it with a new expires_at or remove the grant.")
		return
	}
	users, d := setStrings(ctx, remoteUsers)
	diags.Append(d...)
	if d.HasError() {
		return
	}
	if len(users) == 0 && slices.Contains(accessTypesNeedingUsers, accessType.ValueString()) {
		diags.AddAttributeError(at.AtName("remote_users"), "Missing remote_users",
			accessType.ValueString()+" grants must name the target accounts they allow.")
		return
	}

	grant := compliance.Grant{
		AccessType:  accessType.ValueString(),
		RemoteUsers: users,
		ExpiresAt:   expiry,
	}
	addViolations(diags, at, profile.CheckGrant(grant, now))
}

// setHasUnknown reports whether the set, or any element in it, is not known
// yet. A set built from another resource's output can be known while its
// elements are not.
func setHasUnknown(set types.Set) bool {
	if set.IsUnknown() {
		return true
	}
	for _, v := range set.Elements() {
		if v.IsUnknown() {
			return true
		}
	}
	return false
}

// setStrings reads a fully known set of strings. Null gives nil.
func setStrings(ctx context.Context, set types.Set) ([]string, diag.Diagnostics) {
	if set.IsNull() || set.IsUnknown() {
		return nil, nil
	}
	var out []string
	diags := set.ElementsAs(ctx, &out, false)
	return out, diags
}

func stringSet(in []string) types.Set {
	if len(in) == 0 {
		return types.SetNull(types.StringType)
	}
	elems := make([]attr.Value, 0, len(in))
	for _, v := range in {
		elems = append(elems, types.StringValue(v))
	}
	return types.SetValueMust(types.StringType, elems)
}

// grantPatch is the PATCH body for a grant. Unlike the SDK's request type it
// always sends remote_users, so an empty list clears them.
type grantPatch struct {
	RemoteUsers []string `json:"remote_users"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
	DurationSec *int     `json:"duration_seconds,omitempty"`
}

// patchGrant sets a grant's remote users and expiry. A null expires_at
// clears the expiry, which the API spells duration_seconds = 0.
func patchGrant(ctx context.Context, client *sdk.Client, permID string, remoteUsers []string, expiresAt types.String) (*sdk.Permission, error) {
	body := grantPatch{RemoteUsers: remoteUsers}
	if body.RemoteUsers == nil {
		body.RemoteUsers = []string{}
	}
	if expiresAt.IsNull() {
		zero := 0
		body.DurationSec = &zero
	} else {
		v := expiryRequestValue(expiresAt)
		body.ExpiresAt = &v
	}
	var out sdk.Permission
	if err := client.Do(ctx, http.MethodPatch, "/admin/permissions/"+permID, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// expiryRequestValue sends expires_at in UTC.
func expiryRequestValue(v types.String) string {
	if v.IsNull() {
		return ""
	}
	t, err := time.Parse(time.RFC3339, v.ValueString())
	if err != nil {
		return v.ValueString()
	}
	return t.UTC().Format(time.RFC3339)
}

// expiryValue keeps the configured spelling of expires_at when it names the
// same instant the API returned.
func expiryValue(t *time.Time, prior types.String) types.String {
	if !prior.IsNull() && !prior.IsUnknown() && sameInstant(prior.ValueString(), t) {
		return prior
	}
	return formatExpiry(t)
}
