package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
)

var (
	_ datasource.DataSourceWithConfigure = (*machineDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*userDataSource)(nil)
)

// machineDataSource looks a machine up by name.
type machineDataSource struct {
	data *providerData
}

type machineLookupModel struct {
	Name     types.String            `tfsdk:"name"`
	ID       types.String            `tfsdk:"id"`
	Hostname types.String            `tfsdk:"hostname"`
	Port     types.Int64             `tfsdk:"port"`
	Tags     map[string]types.String `tfsdk:"tags"`
	IsActive types.Bool              `tfsdk:"is_active"`
}

func newMachineDataSource() datasource.DataSource {
	return &machineDataSource{}
}

func (d *machineDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machine"
}

func (d *machineDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Look up a machine by name, e.g. one registered by the console or an install script.",
		Attributes: map[string]schema.Attribute{
			"name":      schema.StringAttribute{Required: true},
			"id":        schema.StringAttribute{Computed: true},
			"hostname":  schema.StringAttribute{Computed: true},
			"port":      schema.Int64Attribute{Computed: true},
			"tags":      schema.MapAttribute{Computed: true, ElementType: types.StringType},
			"is_active": schema.BoolAttribute{Computed: true},
		},
	}
}

func (d *machineDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *machineDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.data, &resp.Diagnostics) {
		return
	}
	var cfg machineLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	machines, err := d.data.client.ListMachines(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot list machines", err.Error())
		return
	}
	var m *sdk.Machine
	for i := range machines {
		if machines[i].Name == cfg.Name.ValueString() {
			m = &machines[i]
		}
	}
	if m == nil {
		resp.Diagnostics.AddError("Machine not found", notFoundDetail("machine", cfg.Name.ValueString(), len(machines)))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, machineLookupModel{
		Name:     types.StringValue(m.Name),
		ID:       types.StringValue(m.ID),
		Hostname: types.StringValue(m.Hostname),
		Port:     types.Int64Value(int64(m.Port)),
		Tags:     stringMapValue(m.Tags),
		IsActive: types.BoolValue(m.IsActive),
	})...)
}

// userDataSource looks a user up by username.
type userDataSource struct {
	data *providerData
}

type userLookupModel struct {
	Username   types.String `tfsdk:"username"`
	ID         types.String `tfsdk:"id"`
	Email      types.String `tfsdk:"email"`
	Role       types.String `tfsdk:"role"`
	MFAEnabled types.Bool   `tfsdk:"mfa_enabled"`
}

func newUserDataSource() datasource.DataSource {
	return &userDataSource{}
}

func (d *userDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (d *userDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Look up a user by username.",
		Attributes: map[string]schema.Attribute{
			"username":    schema.StringAttribute{Required: true},
			"id":          schema.StringAttribute{Computed: true},
			"email":       schema.StringAttribute{Computed: true},
			"role":        schema.StringAttribute{Computed: true},
			"mfa_enabled": schema.BoolAttribute{Computed: true},
		},
	}
}

func (d *userDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *userDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.data, &resp.Diagnostics) {
		return
	}
	var cfg userLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	users, err := d.data.client.ListUsers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot list users", err.Error())
		return
	}
	for _, u := range users {
		if u.Username != cfg.Username.ValueString() {
			continue
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, userLookupModel{
			Username:   types.StringValue(u.Username),
			ID:         types.StringValue(u.ID),
			Email:      types.StringValue(u.Email),
			Role:       types.StringValue(u.EffectiveRole()),
			MFAEnabled: types.BoolValue(u.MFAEnabled),
		})...)
		return
	}
	resp.Diagnostics.AddError("User not found", notFoundDetail("user", cfg.Username.ValueString(), len(users)))
}

func notFoundDetail(kind, name string, listed int) string {
	msg := fmt.Sprintf("no %s named %q", kind, name)
	if listed >= listCap {
		msg += fmt.Sprintf("; the gateway lists only the first %d %ss, so it may exist beyond that", listCap, kind)
	}
	return msg
}
