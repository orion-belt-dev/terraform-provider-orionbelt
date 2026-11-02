package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSourceWithConfigure = (*gatewayDataSource)(nil)

type gatewayDataSource struct {
	data *providerData
}

type gatewayModel struct {
	PublicURL       types.String `tfsdk:"public_url"`
	SSHHost         types.String `tfsdk:"ssh_host"`
	SSHPort         types.Int64  `tfsdk:"ssh_port"`
	SSHCAEnabled    types.Bool   `tfsdk:"ssh_ca_enabled"`
	HostCAPublicKey types.String `tfsdk:"host_ca_public_key"`
	UserCAPublicKey types.String `tfsdk:"user_ca_public_key"`
}

func newGatewayDataSource() datasource.DataSource {
	return &gatewayDataSource{}
}

func (d *gatewayDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gateway"
}

func (d *gatewayDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The gateway's public addresses and SSH certificate authorities.",
		Attributes: map[string]schema.Attribute{
			"public_url":         schema.StringAttribute{Computed: true},
			"ssh_host":           schema.StringAttribute{Computed: true, Description: "Host agents and clients dial."},
			"ssh_port":           schema.Int64Attribute{Computed: true},
			"ssh_ca_enabled":     schema.BoolAttribute{Computed: true},
			"host_ca_public_key": schema.StringAttribute{Computed: true, Description: "Trust this to verify the gateway and agents."},
			"user_ca_public_key": schema.StringAttribute{Computed: true, Description: "Put in TrustedUserCAKeys on targets that accept gateway-issued certificates."},
		},
	}
}

func (d *gatewayDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *gatewayDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.data, &resp.Diagnostics) {
		return
	}
	info, err := d.data.client.GetGatewayInfo(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read gateway info", err.Error())
		return
	}
	ca, err := d.data.client.GetTrustedCA(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read SSH CA", err.Error())
		return
	}

	host := info.PublicSSHHost
	if host == "" {
		host = info.SSHHost
	}
	port := info.PublicSSHPort
	if port == 0 {
		port = info.SSHPort
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, gatewayModel{
		PublicURL:       types.StringValue(info.PublicURL),
		SSHHost:         types.StringValue(host),
		SSHPort:         types.Int64Value(int64(port)),
		SSHCAEnabled:    types.BoolValue(ca.Enabled),
		HostCAPublicKey: types.StringValue(strings.TrimSpace(ca.HostCA)),
		UserCAPublicKey: types.StringValue(strings.TrimSpace(ca.UserCA)),
	})...)
}
