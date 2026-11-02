package provider

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	_ resource.ResourceWithConfigure   = (*machineAccessResource)(nil)
	_ resource.ResourceWithImportState = (*machineAccessResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*machineAccessResource)(nil)
)

// machineAccessResource owns every standing grant on one machine. Grants
// made outside Terraform show up as drift and are revoked on apply.
type machineAccessResource struct {
	data *providerData
}

type machineAccessModel struct {
	ID        types.String `tfsdk:"id"`
	MachineID types.String `tfsdk:"machine_id"`
	Grants    []grantModel `tfsdk:"grant"`
}

type grantModel struct {
	UserID      types.String `tfsdk:"user_id"`
	AccessType  types.String `tfsdk:"access_type"`
	RemoteUsers types.Set    `tfsdk:"remote_users"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}

func newMachineAccessResource() resource.Resource {
	return &machineAccessResource{}
}

func (r *machineAccessResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machine_access"
}

func (r *machineAccessResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The complete list of standing grants on one machine. Any other grant on the machine is revoked. " +
			"Roles (admin, operator) and approved just-in-time requests are not grants and are not affected.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"machine_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: map[string]schema.Block{
			"grant": schema.ListNestedBlock{
				Description: "One grant. Each user_id and access_type pair may appear once.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"user_id": schema.StringAttribute{Required: true},
						"access_type": schema.StringAttribute{
							Required:   true,
							Validators: []validator.String{stringvalidator.OneOf(accessTypes...)},
						},
						"remote_users": schema.SetAttribute{
							ElementType: types.StringType,
							Optional:    true,
							Validators:  []validator.Set{setvalidator.SizeAtLeast(1)},
						},
						"expires_at": schema.StringAttribute{
							Description: "RFC 3339 time the grant stops working. Null means never.",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

func (r *machineAccessResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *machineAccessResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.data == nil {
		return
	}
	var plan machineAccessModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.checkGrants(ctx, &resp.Diagnostics, plan.Grants)
}

func (r *machineAccessResource) checkGrants(ctx context.Context, diags *diag.Diagnostics, grants []grantModel) {
	now := time.Now()
	seen := map[string]bool{}
	for i, g := range grants {
		at := path.Root("grant").AtListIndex(i)
		if !g.UserID.IsUnknown() && !g.AccessType.IsUnknown() {
			key := grantKey(g.UserID.ValueString(), g.AccessType.ValueString())
			if seen[key] {
				diags.AddAttributeError(at, "Duplicate grant",
					fmt.Sprintf("user %s already has a %s grant in this block", g.UserID.ValueString(), g.AccessType.ValueString()))
			}
			seen[key] = true
		}
		checkGrant(ctx, diags, at, r.data.profile, g.AccessType, g.RemoteUsers, g.ExpiresAt, now)
	}
}

func (r *machineAccessResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan machineAccessModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = plan.MachineID
	if err := r.refresh(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Cannot list machine permissions", err.Error())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *machineAccessResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state machineAccessModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.refresh(ctx, &state)
	if isNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot list machine permissions", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *machineAccessResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan machineAccessModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.refresh(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Cannot list machine permissions", err.Error())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *machineAccessResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state machineAccessModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Grants = nil
	r.apply(ctx, state, &resp.Diagnostics)
}

func (r *machineAccessResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("machine_id"), req.ID)...)
}

// apply makes the machine's grants match want: it updates grants that
// changed, creates missing ones and revokes everything else. Revocations run
// last so a failed grant never leaves the machine with less access than
// before by accident.
func (r *machineAccessResource) apply(ctx context.Context, want machineAccessModel, diags *diag.Diagnostics) {
	r.checkGrants(ctx, diags, want.Grants)
	if diags.HasError() {
		return
	}

	machineID := want.MachineID.ValueString()
	current, err := r.data.client.GetMachinePermissions(ctx, machineID)
	if err != nil {
		diags.AddError("Cannot list machine permissions", err.Error())
		return
	}
	byKey := map[string]sdk.Permission{}
	for _, p := range current {
		byKey[grantKey(p.UserID, p.AccessType)] = p
	}

	keep := map[string]bool{}
	for _, g := range want.Grants {
		key := grantKey(g.UserID.ValueString(), g.AccessType.ValueString())
		keep[key] = true
		existing, ok := byKey[key]
		if !ok {
			r.createGrant(ctx, machineID, g, diags)
			continue
		}
		if !grantMatches(ctx, existing, g) {
			r.updateGrant(ctx, existing.ID, g, diags)
		}
	}
	if diags.HasError() {
		return
	}

	for key, p := range byKey {
		if keep[key] {
			continue
		}
		if err := r.data.client.RevokePermission(ctx, p.ID); err != nil && !isNotFound(err) {
			diags.AddError("Cannot revoke permission",
				fmt.Sprintf("permission %s (user %s, %s): %v", p.ID, p.UserID, p.AccessType, err))
		}
	}
}

func (r *machineAccessResource) createGrant(ctx context.Context, machineID string, g grantModel, diags *diag.Diagnostics) {
	users, d := setStrings(ctx, g.RemoteUsers)
	diags.Append(d...)
	_, err := r.data.client.GrantPermission(ctx, sdk.GrantPermissionRequest{
		UserID:      g.UserID.ValueString(),
		MachineID:   machineID,
		AccessType:  g.AccessType.ValueString(),
		RemoteUsers: users,
		ExpiresAt:   expiryRequestValue(g.ExpiresAt),
	})
	if err != nil {
		diags.AddError("Cannot grant permission",
			fmt.Sprintf("user %s, %s: %v", g.UserID.ValueString(), g.AccessType.ValueString(), err))
	}
}

func (r *machineAccessResource) updateGrant(ctx context.Context, permID string, g grantModel, diags *diag.Diagnostics) {
	users, d := setStrings(ctx, g.RemoteUsers)
	diags.Append(d...)
	_, err := patchGrant(ctx, r.data.client, permID, users, g.ExpiresAt)
	if err != nil {
		diags.AddError("Cannot update permission",
			fmt.Sprintf("permission %s (user %s, %s): %v", permID, g.UserID.ValueString(), g.AccessType.ValueString(), err))
	}
}

// refresh replaces m.Grants with what the gateway holds. Grants keep the
// order of the prior list so a plan only shows real changes; grants Terraform
// does not know about are appended, sorted, so they show up as drift.
func (r *machineAccessResource) refresh(ctx context.Context, m *machineAccessModel) error {
	perms, err := r.data.client.GetMachinePermissions(ctx, m.MachineID.ValueString())
	if err != nil {
		return err
	}

	byKey := map[string]sdk.Permission{}
	for _, p := range perms {
		byKey[grantKey(p.UserID, p.AccessType)] = p
	}

	var grants []grantModel
	for _, prior := range m.Grants {
		key := grantKey(prior.UserID.ValueString(), prior.AccessType.ValueString())
		p, ok := byKey[key]
		if !ok {
			continue
		}
		grants = append(grants, permissionToGrant(p, prior))
		delete(byKey, key)
	}

	var unknownKeys []string
	for key := range byKey {
		unknownKeys = append(unknownKeys, key)
	}
	sort.Strings(unknownKeys)
	for _, key := range unknownKeys {
		grants = append(grants, permissionToGrant(byKey[key], grantModel{}))
	}

	m.Grants = grants
	return nil
}

func permissionToGrant(p sdk.Permission, prior grantModel) grantModel {
	return grantModel{
		UserID:      types.StringValue(p.UserID),
		AccessType:  types.StringValue(p.AccessType),
		RemoteUsers: stringSet(p.RemoteUsers),
		ExpiresAt:   expiryValue(p.ExpiresAt, prior.ExpiresAt),
	}
}

func grantMatches(ctx context.Context, p sdk.Permission, g grantModel) bool {
	want, _ := setStrings(ctx, g.RemoteUsers)
	have := slices.Clone(p.RemoteUsers)
	sort.Strings(want)
	sort.Strings(have)
	if !slices.Equal(want, have) {
		return false
	}
	if g.ExpiresAt.IsNull() {
		return p.ExpiresAt == nil
	}
	return sameInstant(g.ExpiresAt.ValueString(), p.ExpiresAt)
}

func grantKey(userID, accessType string) string {
	return userID + "|" + accessType
}
