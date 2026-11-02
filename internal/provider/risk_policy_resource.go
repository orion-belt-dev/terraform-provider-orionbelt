package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/common"
	"github.com/orion-belt-dev/orion-belt/pkg/sdk"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/compliance"
)

var (
	_ resource.ResourceWithConfigure   = (*riskPolicyResource)(nil)
	_ resource.ResourceWithImportState = (*riskPolicyResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*riskPolicyResource)(nil)
)

// riskPolicyResource manages the gateway's single access request policy.
// Destroying it turns both rules off.
type riskPolicyResource struct {
	data *providerData
}

type riskPolicyModel struct {
	ID          types.String      `tfsdk:"id"`
	AutoApprove *autoApproveModel `tfsdk:"auto_approve"`
	Escalate    *escalateModel    `tfsdk:"escalate"`
}

type autoApproveModel struct {
	MaxSensitivity     types.String   `tfsdk:"max_sensitivity"`
	MaxDurationSeconds types.Int64    `tfsdk:"max_duration_seconds"`
	HoursUTC           *hourRange     `tfsdk:"hours_utc"`
	SourceCIDRs        []types.String `tfsdk:"source_cidrs"`
	RequireMFA         types.Bool     `tfsdk:"require_mfa"`
	RemoteUsers        []types.String `tfsdk:"remote_users"`
}

type escalateModel struct {
	Sensitivities      []types.String `tfsdk:"sensitivities"`
	OutsideHoursUTC    *hourRange     `tfsdk:"outside_hours_utc"`
	WithoutMFA         types.Bool     `tfsdk:"without_mfa"`
	SourceOutsideCIDRs []types.String `tfsdk:"source_outside_cidrs"`
}

type hourRange struct {
	Start types.Int64 `tfsdk:"start"`
	End   types.Int64 `tfsdk:"end"`
}

const riskPolicyID = "risk-policy"

func newRiskPolicyResource() resource.Resource {
	return &riskPolicyResource{}
}

func (r *riskPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_risk_policy"
}

func hourRangeAttribute(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Description: description,
		Optional:    true,
		Attributes: map[string]schema.Attribute{
			"start": schema.Int64Attribute{Required: true, Validators: []validator.Int64{int64validator.Between(0, 23)}},
			"end":   schema.Int64Attribute{Required: true, Validators: []validator.Int64{int64validator.Between(0, 24)}},
		},
	}
}

func (r *riskPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "How the gateway routes just-in-time access requests. Leave a block out to turn that rule off. Only one per gateway.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
		Blocks: map[string]schema.Block{
			"auto_approve": schema.SingleNestedBlock{
				Description: "Requests matching every condition are approved without a reviewer.",
				Attributes: map[string]schema.Attribute{
					"max_sensitivity": schema.StringAttribute{
						Description: "Highest machine sensitivity that can be auto-approved: low or medium.",
						Optional:    true,
						Validators:  []validator.String{stringvalidator.OneOf(common.SensitivityLow, common.SensitivityMedium)},
					},
					"max_duration_seconds": schema.Int64Attribute{
						Optional:   true,
						Validators: []validator.Int64{int64validator.Between(1, 24*60*60)},
					},
					"hours_utc": hourRangeAttribute("Only during these UTC hours."),
					"source_cidrs": schema.ListAttribute{
						Description: "Only from these networks.",
						ElementType: types.StringType,
						Optional:    true,
					},
					"require_mfa": falseByDefault(),
					"remote_users": schema.ListAttribute{
						Description: "The only remote accounts that may be auto-approved.",
						ElementType: types.StringType,
						Optional:    true,
					},
				},
			},
			"escalate": schema.SingleNestedBlock{
				Description: "Requests matching any condition need an admin's approval.",
				Attributes: map[string]schema.Attribute{
					"sensitivities": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
					"outside_hours_utc": hourRangeAttribute("Escalate outside these UTC hours."),
					"without_mfa":       falseByDefault(),
					"source_outside_cidrs": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
					},
				},
			},
		},
	}
}

func (r *riskPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *riskPolicyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.data == nil {
		return
	}
	var plan riskPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy := toRiskPolicy(plan)
	if err := policy.Validate(); err != nil {
		resp.Diagnostics.AddError("Invalid risk policy", err.Error())
	}
	addViolations(&resp.Diagnostics, path.Empty(), r.data.profile.CheckRiskPolicy(riskFacts(policy)))
}

func riskFacts(p sdk.RiskPolicy) compliance.RiskPolicy {
	return compliance.RiskPolicy{
		AutoApproveEnabled:     p.AutoApprove.Enabled,
		AutoApproveMaxDuration: time.Duration(p.AutoApprove.MaxDurationSeconds) * time.Second,
		AutoApproveRequireMFA:  p.AutoApprove.RequireMFA,
		AutoApproveRemoteUsers: p.AutoApprove.RemoteUsers,
		EscalateEnabled:        p.Escalate.Enabled,
		EscalateWithoutMFA:     p.Escalate.WithoutMFA,
	}
}

func (r *riskPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan riskPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *riskPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan riskPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, plan, &resp.State, &resp.Diagnostics)
}

func (r *riskPolicyResource) put(ctx context.Context, plan riskPolicyModel, state *tfsdk.State, diags *diag.Diagnostics) {
	if !requireClient(r.data, diags) {
		return
	}
	policy := toRiskPolicy(plan)
	addViolations(diags, path.Empty(), r.data.profile.CheckRiskPolicy(riskFacts(policy)))
	if diags.HasError() {
		return
	}
	saved, err := r.data.client.PutRiskPolicy(ctx, policy)
	if err != nil {
		diags.AddError("Cannot save risk policy", err.Error())
		return
	}
	diags.Append(state.Set(ctx, fromRiskPolicy(saved))...)
}

func (r *riskPolicyResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	policy, err := r.data.client.GetRiskPolicy(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Cannot read risk policy", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, fromRiskPolicy(policy))...)
}

func (r *riskPolicyResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	if _, err := r.data.client.PutRiskPolicy(ctx, sdk.RiskPolicy{}); err != nil {
		resp.Diagnostics.AddError("Cannot reset risk policy", err.Error())
	}
}

func (r *riskPolicyResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), riskPolicyID)...)
}

func toRiskPolicy(m riskPolicyModel) sdk.RiskPolicy {
	var p sdk.RiskPolicy
	if a := m.AutoApprove; a != nil {
		p.AutoApprove = common.AutoApproveRule{
			Enabled:            true,
			MaxSensitivity:     a.MaxSensitivity.ValueString(),
			MaxDurationSeconds: int(a.MaxDurationSeconds.ValueInt64()),
			HoursUTC:           toHourRange(a.HoursUTC),
			SourceCIDRs:        stringValues(a.SourceCIDRs),
			RequireMFA:         a.RequireMFA.ValueBool(),
			RemoteUsers:        stringValues(a.RemoteUsers),
		}
	}
	if e := m.Escalate; e != nil {
		p.Escalate = common.EscalateRule{
			Enabled:            true,
			Sensitivities:      stringValues(e.Sensitivities),
			OutsideHoursUTC:    toHourRange(e.OutsideHoursUTC),
			WithoutMFA:         e.WithoutMFA.ValueBool(),
			SourceOutsideCIDRs: stringValues(e.SourceOutsideCIDRs),
		}
	}
	return p
}

func fromRiskPolicy(p *sdk.RiskPolicy) riskPolicyModel {
	m := riskPolicyModel{ID: types.StringValue(riskPolicyID)}
	if a := p.AutoApprove; a.Enabled {
		m.AutoApprove = &autoApproveModel{
			MaxSensitivity:     optionalString(a.MaxSensitivity),
			MaxDurationSeconds: optionalInt64(a.MaxDurationSeconds),
			HoursUTC:           fromHourRange(a.HoursUTC),
			SourceCIDRs:        optionalList(a.SourceCIDRs),
			RequireMFA:         types.BoolValue(a.RequireMFA),
			RemoteUsers:        optionalList(a.RemoteUsers),
		}
	}
	if e := p.Escalate; e.Enabled {
		m.Escalate = &escalateModel{
			Sensitivities:      optionalList(e.Sensitivities),
			OutsideHoursUTC:    fromHourRange(e.OutsideHoursUTC),
			WithoutMFA:         types.BoolValue(e.WithoutMFA),
			SourceOutsideCIDRs: optionalList(e.SourceOutsideCIDRs),
		}
	}
	return m
}

func toHourRange(h *hourRange) *common.HourRange {
	if h == nil {
		return nil
	}
	return &common.HourRange{Start: int(h.Start.ValueInt64()), End: int(h.End.ValueInt64())}
}

func fromHourRange(h *common.HourRange) *hourRange {
	if h == nil {
		return nil
	}
	return &hourRange{Start: types.Int64Value(int64(h.Start)), End: types.Int64Value(int64(h.End))}
}

// The optional* helpers map Go zero values to null so an omitted attribute
// reads back as omitted rather than as a diff.

func optionalString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func optionalInt64(n int) types.Int64 {
	if n == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(int64(n))
}

func falseByDefault() schema.BoolAttribute {
	return schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)}
}

func optionalList(in []string) []types.String {
	if len(in) == 0 {
		return nil
	}
	return stringList(in)
}
