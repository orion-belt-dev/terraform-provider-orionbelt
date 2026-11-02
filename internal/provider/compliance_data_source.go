package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSourceWithConfigure = (*complianceProfileDataSource)(nil)

// complianceProfileDataSource exposes the rules the provider enforces and
// the controls each one supports, for evidence exports.
type complianceProfileDataSource struct {
	data *providerData
}

type complianceProfileModel struct {
	Frameworks []types.String     `tfsdk:"frameworks"`
	Rules      []ruleSettingModel `tfsdk:"rules"`
}

type ruleSettingModel struct {
	Rule     types.String   `tfsdk:"rule"`
	Setting  types.String   `tfsdk:"setting"`
	Controls []types.String `tfsdk:"controls"`
}

func newComplianceProfileDataSource() datasource.DataSource {
	return &complianceProfileDataSource{}
}

func (d *complianceProfileDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_profile"
}

func (d *complianceProfileDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The compliance rules this provider enforces and the framework controls they support.",
		Attributes: map[string]schema.Attribute{
			"frameworks": schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"rule":     schema.StringAttribute{Computed: true},
						"setting":  schema.StringAttribute{Computed: true},
						"controls": schema.ListAttribute{Computed: true, ElementType: types.StringType},
					},
				},
			},
		},
	}
}

func (d *complianceProfileDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *complianceProfileDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.data == nil {
		resp.Diagnostics.AddError("Provider not configured", "The orionbelt provider has not been configured.")
		return
	}
	out := complianceProfileModel{
		Frameworks: stringList(d.data.profile.Frameworks),
		Rules:      []ruleSettingModel{},
	}
	for _, r := range d.data.profile.Rules() {
		out.Rules = append(out.Rules, ruleSettingModel{
			Rule:     types.StringValue(r.Rule),
			Setting:  types.StringValue(r.Setting),
			Controls: stringList(r.Controls),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, out)...)
}
