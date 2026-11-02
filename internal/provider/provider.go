package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/compliance"
)

var _ provider.Provider = (*orionBeltProvider)(nil)

type orionBeltProvider struct {
	version string
}

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &orionBeltProvider{version: version}
	}
}

// providerData is handed to every resource and data source.
type providerData struct {
	client  *sdk.Client
	profile compliance.Profile
}

type providerModel struct {
	URL          types.String     `tfsdk:"url"`
	APIKey       types.String     `tfsdk:"api_key"`
	CACertPEM    types.String     `tfsdk:"ca_cert_pem"`
	InsecureHTTP types.Bool       `tfsdk:"insecure_http"`
	Timeout      types.String     `tfsdk:"timeout"`
	Compliance   *complianceModel `tfsdk:"compliance"`
}

type complianceModel struct {
	Frameworks        types.List   `tfsdk:"frameworks"`
	MaxGrantDuration  types.String `tfsdk:"max_grant_duration"`
	DeniedRemoteUsers types.List   `tfsdk:"denied_remote_users"`
}

func (p *orionBeltProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "orionbelt"
	resp.Version = p.version
}

func (p *orionBeltProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage an Orion Belt access gateway.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Description: "Gateway base URL, e.g. https://orion.example.com. Defaults to ORIONBELT_URL.",
				Optional:    true,
			},
			"api_key": schema.StringAttribute{
				Description: "Admin or operator API key. Defaults to ORIONBELT_API_KEY.",
				Optional:    true,
				Sensitive:   true,
			},
			"ca_cert_pem": schema.StringAttribute{
				Description: "PEM CA bundle that signs the gateway's TLS certificate. Replaces the system roots.",
				Optional:    true,
			},
			"insecure_http": schema.BoolAttribute{
				Description: "Allow a plain http:// URL. Only for local labs: the API key is sent in clear text.",
				Optional:    true,
			},
			"timeout": schema.StringAttribute{
				Description: "Per-request timeout as a Go duration. Default 30s.",
				Optional:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"compliance": schema.SingleNestedBlock{
				Description: "Compliance frameworks every resource must satisfy. Plans and applies fail on any violation.",
				Attributes: map[string]schema.Attribute{
					"frameworks": schema.ListAttribute{
						Description: "Frameworks to enforce: soc2, iso27001, pci-dss-4.",
						ElementType: types.StringType,
						Optional:    true,
					},
					"max_grant_duration": schema.StringAttribute{
						Description: "Tighter limit on how far in the future a grant may expire, e.g. 8h or 720h.",
						Optional:    true,
					},
					"denied_remote_users": schema.ListAttribute{
						Description: "Remote accounts no grant may name, in addition to the frameworks' list.",
						ElementType: types.StringType,
						Optional:    true,
					},
				},
			},
		},
	}
}

func (p *orionBeltProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	profile, err := buildProfile(ctx, cfg.Compliance)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("compliance"), "Invalid compliance configuration", err.Error())
		return
	}

	url := stringOrEnv(cfg.URL, "ORIONBELT_URL")
	apiKey := stringOrEnv(cfg.APIKey, "ORIONBELT_API_KEY")
	if cfg.URL.IsUnknown() || cfg.APIKey.IsUnknown() || cfg.CACertPEM.IsUnknown() || cfg.Timeout.IsUnknown() || cfg.InsecureHTTP.IsUnknown() {
		// Values come from resources not created yet; resources will
		// report the missing client if they need it during this plan.
		resp.DataSourceData = &providerData{profile: profile}
		resp.ResourceData = &providerData{profile: profile}
		return
	}
	if url == "" {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "Missing gateway URL", "Set url or ORIONBELT_URL.")
	}
	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Missing API key", "Set api_key or ORIONBELT_API_KEY.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	timeout := 30 * time.Second
	if !cfg.Timeout.IsNull() {
		timeout, err = time.ParseDuration(cfg.Timeout.ValueString())
		if err != nil || timeout <= 0 {
			resp.Diagnostics.AddAttributeError(path.Root("timeout"), "Invalid timeout", "Use a positive Go duration such as 30s.")
			return
		}
	}

	httpClient, err := newHTTPClient(url, cfg.CACertPEM.ValueString(), cfg.InsecureHTTP.ValueBool(), timeout)
	if err != nil {
		resp.Diagnostics.AddError("Invalid gateway connection settings", err.Error())
		return
	}

	client, err := sdk.NewClient(url,
		sdk.WithAPIKey(apiKey),
		sdk.WithHTTPClient(httpClient),
		sdk.WithUserAgent("terraform-provider-orionbelt/"+p.version),
	)
	if err != nil {
		resp.Diagnostics.AddError("Cannot create Orion Belt client", err.Error())
		return
	}

	data := &providerData{client: client, profile: profile}
	resp.DataSourceData = data
	resp.ResourceData = data
}

// buildProfile reads the compliance block. Every value must be known when
// the provider is configured: a profile that silently started empty would
// let a plan through unchecked.
func buildProfile(ctx context.Context, m *complianceModel) (compliance.Profile, error) {
	if m == nil {
		return compliance.NewProfile(nil, compliance.Overrides{})
	}
	if m.Frameworks.IsUnknown() || m.MaxGrantDuration.IsUnknown() || m.DeniedRemoteUsers.IsUnknown() {
		return compliance.Profile{}, errors.New("compliance settings must be known at plan time; do not derive them from resources")
	}
	frameworks, err := listStrings(ctx, m.Frameworks)
	if err != nil {
		return compliance.Profile{}, err
	}
	denied, err := listStrings(ctx, m.DeniedRemoteUsers)
	if err != nil {
		return compliance.Profile{}, err
	}
	var overrides compliance.Overrides
	if !m.MaxGrantDuration.IsNull() {
		d, err := time.ParseDuration(m.MaxGrantDuration.ValueString())
		if err != nil || d <= 0 {
			return compliance.Profile{}, errInvalidDuration("max_grant_duration", m.MaxGrantDuration.ValueString())
		}
		overrides.MaxGrantDuration = d
	}
	overrides.DeniedRemoteUsers = denied
	return compliance.NewProfile(frameworks, overrides)
}

func listStrings(ctx context.Context, list types.List) ([]string, error) {
	if list.IsNull() {
		return nil, nil
	}
	var out []string
	if diags := list.ElementsAs(ctx, &out, false); diags.HasError() {
		return nil, fmt.Errorf("compliance: %v", diags.Errors())
	}
	return out, nil
}

func (p *orionBeltProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newUserResource,
		newPermissionResource,
		newMachineAccessResource,
		newAgentResource,
		newRiskPolicyResource,
	}
}

func (p *orionBeltProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newGatewayDataSource,
		newMachineDataSource,
		newUserDataSource,
		newAccessReviewDataSource,
		newComplianceProfileDataSource,
	}
}

func stringOrEnv(v types.String, env string) string {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueString()
	}
	return os.Getenv(env)
}
