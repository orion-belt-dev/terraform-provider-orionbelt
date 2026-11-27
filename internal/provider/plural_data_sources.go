package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
)

var (
	_ datasource.DataSourceWithConfigure = (*machinesDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*usersDataSource)(nil)
)

// machinesDataSource lists machines that match every filter given.
type machinesDataSource struct {
	data *providerData
}

type machinesModel struct {
	NamePrefix types.String            `tfsdk:"name_prefix"`
	Tags       map[string]types.String `tfsdk:"tags"`
	ActiveOnly types.Bool              `tfsdk:"active_only"`
	Machines   []machineItemModel      `tfsdk:"machines"`
}

type machineItemModel struct {
	ID       types.String            `tfsdk:"id"`
	Name     types.String            `tfsdk:"name"`
	Hostname types.String            `tfsdk:"hostname"`
	Port     types.Int64             `tfsdk:"port"`
	Tags     map[string]types.String `tfsdk:"tags"`
	IsActive types.Bool              `tfsdk:"is_active"`
}

func newMachinesDataSource() datasource.DataSource {
	return &machinesDataSource{}
}

func (d *machinesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machines"
}

func (d *machinesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "List machines matching every filter given, sorted by name. With no filters, lists every machine.",
		Attributes: map[string]schema.Attribute{
			"name_prefix": schema.StringAttribute{
				Description: "Only machines whose name starts with this.",
				Optional:    true,
			},
			"tags": schema.MapAttribute{
				Description: "Only machines that carry every one of these tags with the same value.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"active_only": schema.BoolAttribute{
				Description: "Only machines the gateway marks active.",
				Optional:    true,
			},
			"machines": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":        schema.StringAttribute{Computed: true},
						"name":      schema.StringAttribute{Computed: true},
						"hostname":  schema.StringAttribute{Computed: true},
						"port":      schema.Int64Attribute{Computed: true},
						"tags":      schema.MapAttribute{Computed: true, ElementType: types.StringType},
						"is_active": schema.BoolAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *machinesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *machinesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.data, &resp.Diagnostics) {
		return
	}
	var cfg machinesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	machines, err := d.data.client.ListMachines(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot list machines", err.Error())
		return
	}
	warnIfTruncated(&resp.Diagnostics, "machine", len(machines))

	want := stringMap(cfg.Tags)
	cfg.Machines = []machineItemModel{}
	for _, m := range machines {
		if !machineMatches(m, cfg.NamePrefix.ValueString(), want, cfg.ActiveOnly.ValueBool()) {
			continue
		}
		cfg.Machines = append(cfg.Machines, machineItemModel{
			ID:       types.StringValue(m.ID),
			Name:     types.StringValue(m.Name),
			Hostname: types.StringValue(m.Hostname),
			Port:     types.Int64Value(int64(m.Port)),
			Tags:     stringMapValue(m.Tags),
			IsActive: types.BoolValue(m.IsActive),
		})
	}
	sort.Slice(cfg.Machines, func(i, j int) bool {
		return cfg.Machines[i].Name.ValueString() < cfg.Machines[j].Name.ValueString()
	})
	resp.Diagnostics.Append(resp.State.Set(ctx, cfg)...)
}

func machineMatches(m sdk.Machine, prefix string, tags map[string]string, activeOnly bool) bool {
	if !strings.HasPrefix(m.Name, prefix) || (activeOnly && !m.IsActive) {
		return false
	}
	for k, v := range tags {
		if got, ok := m.Tags[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// usersDataSource lists users that match every filter given.
type usersDataSource struct {
	data *providerData
}

type usersModel struct {
	UsernamePrefix types.String    `tfsdk:"username_prefix"`
	Role           types.String    `tfsdk:"role"`
	Users          []userItemModel `tfsdk:"users"`
}

type userItemModel struct {
	ID         types.String `tfsdk:"id"`
	Username   types.String `tfsdk:"username"`
	Email      types.String `tfsdk:"email"`
	Role       types.String `tfsdk:"role"`
	MFAEnabled types.Bool   `tfsdk:"mfa_enabled"`
}

func newUsersDataSource() datasource.DataSource {
	return &usersDataSource{}
}

func (d *usersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_users"
}

func (d *usersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "List users matching every filter given, sorted by username. With no filters, lists every user.",
		Attributes: map[string]schema.Attribute{
			"username_prefix": schema.StringAttribute{
				Description: "Only users whose username starts with this.",
				Optional:    true,
			},
			"role": schema.StringAttribute{
				Description: "Only users with this role: admin, operator, auditor or user.",
				Optional:    true,
				Validators:  []validator.String{stringvalidator.OneOf("admin", "operator", "auditor", "user")},
			},
			"users": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":          schema.StringAttribute{Computed: true},
						"username":    schema.StringAttribute{Computed: true},
						"email":       schema.StringAttribute{Computed: true},
						"role":        schema.StringAttribute{Computed: true},
						"mfa_enabled": schema.BoolAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *usersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *usersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.data, &resp.Diagnostics) {
		return
	}
	var cfg usersModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	users, err := d.data.client.ListUsers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot list users", err.Error())
		return
	}
	warnIfTruncated(&resp.Diagnostics, "user", len(users))

	role := cfg.Role.ValueString()
	cfg.Users = []userItemModel{}
	for _, u := range users {
		if !strings.HasPrefix(u.Username, cfg.UsernamePrefix.ValueString()) {
			continue
		}
		if role != "" && u.EffectiveRole() != role {
			continue
		}
		cfg.Users = append(cfg.Users, userItemModel{
			ID:         types.StringValue(u.ID),
			Username:   types.StringValue(u.Username),
			Email:      types.StringValue(u.Email),
			Role:       types.StringValue(u.EffectiveRole()),
			MFAEnabled: types.BoolValue(u.MFAEnabled),
		})
	}
	sort.Slice(cfg.Users, func(i, j int) bool {
		return cfg.Users[i].Username.ValueString() < cfg.Users[j].Username.ValueString()
	})
	resp.Diagnostics.Append(resp.State.Set(ctx, cfg)...)
}

// warnIfTruncated warns when the gateway returned a full page, since its
// lists have no paging and anything beyond listCap is silently left out.
func warnIfTruncated(diags *diag.Diagnostics, kind string, listed int) {
	if listed < listCap {
		return
	}
	diags.AddWarning(
		fmt.Sprintf("Gateway returned only the first %d %ss", listCap, kind),
		fmt.Sprintf("The gateway's %s list has no paging, so %ss beyond the first %d are not included.", kind, kind, listCap),
	)
}
