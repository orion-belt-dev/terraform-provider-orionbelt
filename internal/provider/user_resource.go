package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/compliance"
)

var (
	_ resource.ResourceWithConfigure   = (*userResource)(nil)
	_ resource.ResourceWithImportState = (*userResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*userResource)(nil)
)

type userResource struct {
	data *providerData
}

type userModel struct {
	ID         types.String `tfsdk:"id"`
	Username   types.String `tfsdk:"username"`
	Email      types.String `tfsdk:"email"`
	Role       types.String `tfsdk:"role"`
	PublicKey  types.String `tfsdk:"public_key"`
	MFAEnabled types.Bool   `tfsdk:"mfa_enabled"`
}

func newUserResource() resource.Resource {
	return &userResource{}
}

func (r *userResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *userResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A person who can sign in to the gateway.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"username": schema.StringAttribute{
				Description:   "Login name. Changing it replaces the user.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.LengthBetween(1, 64)},
			},
			"email": schema.StringAttribute{
				Required: true,
			},
			"role": schema.StringAttribute{
				Description: "admin, operator, auditor or user. Default user.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("user"),
				Validators:  []validator.String{stringvalidator.OneOf("admin", "operator", "auditor", "user")},
			},
			"public_key": schema.StringAttribute{
				Description: "SSH public key in authorized_keys format.",
				Optional:    true,
			},
			"mfa_enabled": schema.BoolAttribute{
				Description: "Whether the user has enrolled TOTP. Users enrol themselves.",
				Computed:    true,
			},
		},
	}
}

func (r *userResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *userResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.data == nil {
		return
	}
	var plan userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	addViolations(&resp.Diagnostics, path.Empty(), r.data.profile.CheckUser(userFacts(plan)))
}

func userFacts(m userModel) compliance.User {
	return compliance.User{
		Username: m.Username.ValueString(),
		Email:    m.Email.ValueString(),
	}
}

func (r *userResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	addViolations(&resp.Diagnostics, path.Empty(), r.data.profile.CheckUser(userFacts(plan)))
	if resp.Diagnostics.HasError() {
		return
	}

	role := plan.Role.ValueString()
	user, err := r.data.client.CreateUser(ctx, sdk.CreateUserRequest{
		Username:  plan.Username.ValueString(),
		Email:     plan.Email.ValueString(),
		PublicKey: plan.PublicKey.ValueString(),
		Role:      role,
		IsAdmin:   role == "admin",
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot create user", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, userToModel(user, plan))...)
}

func (r *userResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state userModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	user, err := r.data.client.GetUser(ctx, state.ID.ValueString())
	if isNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot read user", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, userToModel(user, state))...)
}

func (r *userResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan, state userModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	addViolations(&resp.Diagnostics, path.Empty(), r.data.profile.CheckUser(userFacts(plan)))
	if resp.Diagnostics.HasError() {
		return
	}

	email := plan.Email.ValueString()
	role := plan.Role.ValueString()
	isAdmin := role == "admin"
	publicKey := plan.PublicKey.ValueString()
	user, err := r.data.client.UpdateUser(ctx, state.ID.ValueString(), sdk.UpdateUserRequest{
		Email:     &email,
		Role:      &role,
		IsAdmin:   &isAdmin,
		PublicKey: &publicKey,
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot update user", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, userToModel(user, plan))...)
}

func (r *userResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state userModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.data.client.DeleteUser(ctx, state.ID.ValueString())
	if err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Cannot delete user", err.Error())
	}
}

func (r *userResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// userToModel copies the API's view into the model. The public key keeps
// the configured spelling when the server returns the same key with
// different whitespace.
func userToModel(u *sdk.User, prior userModel) userModel {
	m := userModel{
		ID:         types.StringValue(u.ID),
		Username:   types.StringValue(u.Username),
		Email:      types.StringValue(u.Email),
		Role:       types.StringValue(u.EffectiveRole()),
		MFAEnabled: types.BoolValue(u.MFAEnabled),
		PublicKey:  types.StringNull(),
	}
	if u.PublicKey != "" {
		m.PublicKey = types.StringValue(u.PublicKey)
		if sameKey(prior.PublicKey.ValueString(), u.PublicKey) {
			m.PublicKey = prior.PublicKey
		}
	}
	return m
}
