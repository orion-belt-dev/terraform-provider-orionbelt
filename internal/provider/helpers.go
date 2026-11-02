package provider

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
	"golang.org/x/crypto/ssh"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/compliance"
)

func isNotFound(err error) bool {
	var apiErr *sdk.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

func errInvalidDuration(field, value string) error {
	return fmt.Errorf("%s: %q is not a positive Go duration such as 8h", field, value)
}

// providerDataFrom unpacks the value Configure handed to a resource or
// data source. It returns nil before Configure has run.
func providerDataFrom(data any, diags *diag.Diagnostics) *providerData {
	if data == nil {
		return nil
	}
	pd, ok := data.(*providerData)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("got %T", data))
		return nil
	}
	return pd
}

// requireClient reports an error when the provider has no client, which
// happens when url or api_key were unknown at plan time.
func requireClient(pd *providerData, diags *diag.Diagnostics) bool {
	if pd == nil || pd.client == nil {
		diags.AddError("Provider not configured", "The orionbelt provider has no url or api_key yet.")
		return false
	}
	return true
}

// addViolations turns compliance violations into attribute errors. prefix
// locates the object the violations belong to, e.g. grant[2].
func addViolations(diags *diag.Diagnostics, prefix path.Path, violations []compliance.Violation) {
	for _, v := range violations {
		diags.AddAttributeError(
			prefix.AtName(v.Field),
			"Compliance violation: "+v.Rule,
			v.Error(),
		)
	}
}

func stringValues(in []types.String) []string {
	var out []string
	for _, v := range in {
		if !v.IsNull() && !v.IsUnknown() {
			out = append(out, v.ValueString())
		}
	}
	return out
}

func stringList(in []string) []types.String {
	out := make([]types.String, 0, len(in))
	for _, v := range in {
		out = append(out, types.StringValue(v))
	}
	return out
}

func stringMap(in map[string]types.String) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v.ValueString()
	}
	return out
}

func stringMapValue(in map[string]string) map[string]types.String {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]types.String, len(in))
	for k, v := range in {
		out[k] = types.StringValue(v)
	}
	return out
}

// parseExpiry reads an RFC 3339 expires_at. Null means the grant never
// expires.
func parseExpiry(v types.String) (*time.Time, error) {
	if v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v.ValueString())
	if err != nil {
		return nil, fmt.Errorf("expires_at %q is not an RFC 3339 timestamp such as 2026-12-31T18:00:00Z", v.ValueString())
	}
	return &t, nil
}

func formatExpiry(t *time.Time) types.String {
	if t == nil {
		return types.StringNull()
	}
	return types.StringValue(t.UTC().Format(time.RFC3339))
}

// sameKey reports whether two authorized_keys lines hold the same key,
// ignoring comments and whitespace.
func sameKey(a, b string) bool {
	ka, _, _, _, errA := ssh.ParseAuthorizedKey([]byte(a))
	kb, _, _, _, errB := ssh.ParseAuthorizedKey([]byte(b))
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(ka.Marshal(), kb.Marshal())
}

// expiryTolerance absorbs the gateway storing a new grant's expiry as now
// plus the remaining duration, which lands a few milliseconds late.
const expiryTolerance = 2 * time.Second

// sameInstant reports whether an RFC 3339 string and a time are the same
// moment, so "+01:00" in config does not fight "Z" from the API.
func sameInstant(s string, t *time.Time) bool {
	if t == nil {
		return s == ""
	}
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return false
	}
	diff := parsed.Sub(*t)
	return diff < expiryTolerance && diff > -expiryTolerance
}

// listCap is the most rows the gateway's machine and user lists return; they
// have no paging. A full page means some rows may be missing.
const listCap = 100
