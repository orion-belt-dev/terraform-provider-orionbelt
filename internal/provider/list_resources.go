package provider

import (
	"context"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
)

// The list resources back `terraform query` (Terraform 1.14+), which finds
// objects already on the gateway and writes import blocks for them. Each
// embeds its managed resource for Metadata, Configure and the API mapping.
var (
	_ list.ListResourceWithConfigure = (*userListResource)(nil)
	_ list.ListResourceWithConfigure = (*machineAccessListResource)(nil)
)

type userListResource struct {
	userResource
}

type userListConfig struct {
	UsernamePrefix types.String `tfsdk:"username_prefix"`
	Role           types.String `tfsdk:"role"`
}

func newUserListResource() list.ListResource {
	return &userListResource{}
}

func (r *userListResource) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "Find users on the gateway, sorted by username.",
		Attributes: map[string]listschema.Attribute{
			"username_prefix": listschema.StringAttribute{
				Description: "Only users whose username starts with this.",
				Optional:    true,
			},
			"role": listschema.StringAttribute{
				Description: "Only users with this role: admin, operator, auditor or user.",
				Optional:    true,
				Validators:  []validator.String{stringvalidator.OneOf("admin", "operator", "auditor", "user")},
			},
		},
	}
}

func (r *userListResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	var diags diag.Diagnostics
	if !requireClient(r.data, &diags) {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}
	var cfg userListConfig
	diags.Append(req.Config.Get(ctx, &cfg)...)
	if diags.HasError() {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}
	users, err := r.data.client.ListUsers(ctx)
	if err != nil {
		diags.AddError("Cannot list users", err.Error())
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}

	role := cfg.Role.ValueString()
	var matched []sdk.User
	for _, u := range users {
		if strings.HasPrefix(u.Username, cfg.UsernamePrefix.ValueString()) && (role == "" || u.EffectiveRole() == role) {
			matched = append(matched, u)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Username < matched[j].Username })

	stream.Results = func(push func(list.ListResult) bool) {
		for i := range resultCount(len(matched), req.Limit) {
			u := &matched[i]
			result := req.NewListResult(ctx)
			result.DisplayName = u.Username
			result.Diagnostics.Append(result.Identity.Set(ctx, userIdentityModel{ID: types.StringValue(u.ID)})...)
			if req.IncludeResource {
				result.Diagnostics.Append(result.Resource.Set(ctx, userToModel(u, userModel{}))...)
			}
			if !push(result) {
				return
			}
		}
	}
}

type machineAccessListResource struct {
	machineAccessResource
}

type machineAccessListConfig struct {
	NamePrefix types.String            `tfsdk:"name_prefix"`
	Tags       map[string]types.String `tfsdk:"tags"`
}

func newMachineAccessListResource() list.ListResource {
	return &machineAccessListResource{}
}

func (r *machineAccessListResource) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		Description: "Find machines whose grants can be brought under orionbelt_machine_access, sorted by machine name. " +
			"Importing one adopts every standing grant the machine has.",
		Attributes: map[string]listschema.Attribute{
			"name_prefix": listschema.StringAttribute{
				Description: "Only machines whose name starts with this.",
				Optional:    true,
			},
			"tags": listschema.MapAttribute{
				Description: "Only machines that carry every one of these tags with the same value.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *machineAccessListResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	var diags diag.Diagnostics
	if !requireClient(r.data, &diags) {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}
	var cfg machineAccessListConfig
	diags.Append(req.Config.Get(ctx, &cfg)...)
	if diags.HasError() {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}
	machines, err := r.data.client.ListMachines(ctx)
	if err != nil {
		diags.AddError("Cannot list machines", err.Error())
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}

	want := stringMap(cfg.Tags)
	var matched []sdk.Machine
	for _, m := range machines {
		if machineMatches(m, cfg.NamePrefix.ValueString(), want, false) {
			matched = append(matched, m)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })

	stream.Results = func(push func(list.ListResult) bool) {
		for i := range resultCount(len(matched), req.Limit) {
			m := matched[i]
			result := req.NewListResult(ctx)
			result.DisplayName = m.Name
			result.Diagnostics.Append(result.Identity.Set(ctx, machineAccessIdentityModel{MachineID: types.StringValue(m.ID)})...)
			if req.IncludeResource {
				model := machineAccessModel{ID: types.StringValue(m.ID), MachineID: types.StringValue(m.ID)}
				if err := r.refresh(ctx, &model); err != nil {
					result.Diagnostics.AddError("Cannot list machine permissions", err.Error())
				} else {
					result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
				}
			}
			if !push(result) {
				return
			}
		}
	}
}

// resultCount caps n at the limit Terraform asked for; zero means no limit.
func resultCount(n int, limit int64) int {
	if limit > 0 && int64(n) > limit {
		return int(limit)
	}
	return n
}
