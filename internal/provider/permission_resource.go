package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
)

var (
	_ resource.ResourceWithConfigure   = (*permissionResource)(nil)
	_ resource.ResourceWithImportState = (*permissionResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*permissionResource)(nil)
)

type permissionResource struct {
	data *providerData
}

type permissionModel struct {
	ID          types.String `tfsdk:"id"`
	UserID      types.String `tfsdk:"user_id"`
	MachineID   types.String `tfsdk:"machine_id"`
	AccessType  types.String `tfsdk:"access_type"`
	RemoteUsers types.Set    `tfsdk:"remote_users"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
	GrantedBy   types.String `tfsdk:"granted_by"`
	GrantedAt   types.String `tfsdk:"granted_at"`
}

func newPermissionResource() resource.Resource {
	return &permissionResource{}
}

func (r *permissionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permission"
}

func (r *permissionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "One standing access grant: a user on a machine. Do not combine with orionbelt_machine_access on the same machine.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"user_id":    schema.StringAttribute{Required: true, PlanModifiers: replace},
			"machine_id": schema.StringAttribute{Required: true, PlanModifiers: replace},
			"access_type": schema.StringAttribute{
				Description:   "ssh, scp, both, rdp, vnc or k8s.",
				Required:      true,
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.OneOf(accessTypes...)},
			},
			"remote_users": schema.SetAttribute{
				Description: "Accounts on the target (or namespace/role scopes for k8s).",
				ElementType: types.StringType,
				Optional:    true,
				Validators:  []validator.Set{setvalidator.SizeAtLeast(1)},
			},
			"expires_at": schema.StringAttribute{
				Description: "RFC 3339 time the grant stops working. Null means never.",
				Optional:    true,
			},
			"granted_by": schema.StringAttribute{
				Description: "Who last changed the grant. The gateway resets it on every update.",
				Computed:    true,
			},
			"granted_at": schema.StringAttribute{
				Description: "When the grant last changed. The gateway resets it on every update.",
				Computed:    true,
			},
		},
	}
}

func (r *permissionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *permissionResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.data == nil {
		return
	}
	var plan permissionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	checkGrant(ctx, &resp.Diagnostics, path.Empty(), r.data.profile, plan.AccessType, plan.RemoteUsers, plan.ExpiresAt, time.Now())
}

func (r *permissionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan permissionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	checkGrant(ctx, &resp.Diagnostics, path.Empty(), r.data.profile, plan.AccessType, plan.RemoteUsers, plan.ExpiresAt, time.Now())
	if resp.Diagnostics.HasError() {
		return
	}

	// The API upserts on (user, machine, access type). Refuse to adopt a
	// grant someone made by hand; it must be imported so the change is
	// visible in the plan.
	existing, err := r.findGrant(ctx, plan.MachineID.ValueString(), func(p sdk.Permission) bool {
		return p.UserID == plan.UserID.ValueString() && p.AccessType == plan.AccessType.ValueString()
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot list machine permissions", err.Error())
		return
	}
	if existing != nil {
		resp.Diagnostics.AddError("Grant already exists",
			fmt.Sprintf("User %s already has %s access to machine %s (permission %s). Import it with id %q.",
				existing.UserID, existing.AccessType, existing.MachineID, existing.ID, existing.MachineID+"/"+existing.ID))
		return
	}

	users, diags := setStrings(ctx, plan.RemoteUsers)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	perm, err := r.data.client.GrantPermission(ctx, sdk.GrantPermissionRequest{
		UserID:      plan.UserID.ValueString(),
		MachineID:   plan.MachineID.ValueString(),
		AccessType:  plan.AccessType.ValueString(),
		RemoteUsers: users,
		ExpiresAt:   expiryRequestValue(plan.ExpiresAt),
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot grant permission", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, permissionToModel(perm, plan))...)
}

func (r *permissionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state permissionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	perm, err := r.findGrant(ctx, state.MachineID.ValueString(), func(p sdk.Permission) bool {
		return p.ID == state.ID.ValueString()
	})
	if isNotFound(err) || (err == nil && perm == nil) {
		// Revoked or expired: Terraform will plan to grant it again, and
		// checkGrant stops that plan if expires_at is now in the past.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot read permission", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, permissionToModel(perm, state))...)
}

func (r *permissionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan, state permissionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	checkGrant(ctx, &resp.Diagnostics, path.Empty(), r.data.profile, plan.AccessType, plan.RemoteUsers, plan.ExpiresAt, time.Now())
	if resp.Diagnostics.HasError() {
		return
	}

	users, diags := setStrings(ctx, plan.RemoteUsers)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	perm, err := patchGrant(ctx, r.data.client, state.ID.ValueString(), users, plan.ExpiresAt)
	if err != nil {
		resp.Diagnostics.AddError("Cannot update permission", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, permissionToModel(perm, plan))...)
}

func (r *permissionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state permissionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.data.client.RevokePermission(ctx, state.ID.ValueString())
	if err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Cannot revoke permission", err.Error())
	}
}

// ImportState takes "<machine_id>/<permission_id>".
func (r *permissionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	machineID, permID, ok := strings.Cut(req.ID, "/")
	if !ok || machineID == "" || permID == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use <machine_id>/<permission_id>.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("machine_id"), machineID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), permID)...)
}

func (r *permissionResource) findGrant(ctx context.Context, machineID string, match func(sdk.Permission) bool) (*sdk.Permission, error) {
	perms, err := r.data.client.GetMachinePermissions(ctx, machineID)
	if err != nil {
		return nil, err
	}
	for i := range perms {
		if match(perms[i]) {
			return &perms[i], nil
		}
	}
	return nil, nil
}

func permissionToModel(p *sdk.Permission, prior permissionModel) permissionModel {
	m := permissionModel{
		ID:          types.StringValue(p.ID),
		UserID:      types.StringValue(p.UserID),
		MachineID:   types.StringValue(p.MachineID),
		AccessType:  types.StringValue(p.AccessType),
		RemoteUsers: stringSet(p.RemoteUsers),
		ExpiresAt:   expiryValue(p.ExpiresAt, prior.ExpiresAt),
		GrantedBy:   types.StringValue(p.GrantedBy),
		GrantedAt:   types.StringValue(p.GrantedAt.UTC().Format(time.RFC3339)),
	}
	return m
}
