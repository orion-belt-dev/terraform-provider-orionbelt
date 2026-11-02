package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/compliance"
)

var _ datasource.DataSourceWithConfigure = (*accessReviewDataSource)(nil)

// accessReviewDataSource lists who can reach what right now, and which of
// those grants break the compliance profile. Export it on a schedule as
// access review evidence.
type accessReviewDataSource struct {
	data *providerData
}

type accessReviewModel struct {
	MachineIDs  []types.String  `tfsdk:"machine_ids"`
	GeneratedAt types.String    `tfsdk:"generated_at"`
	Frameworks  []types.String  `tfsdk:"frameworks"`
	Entries     []accessEntry   `tfsdk:"entries"`
	Findings    []accessFinding `tfsdk:"findings"`
	Compliant   types.Bool      `tfsdk:"compliant"`
}

type accessEntry struct {
	UserID      types.String   `tfsdk:"user_id"`
	Username    types.String   `tfsdk:"username"`
	MachineID   types.String   `tfsdk:"machine_id"`
	MachineName types.String   `tfsdk:"machine_name"`
	AccessType  types.String   `tfsdk:"access_type"`
	RemoteUsers []types.String `tfsdk:"remote_users"`
	Source      types.String   `tfsdk:"source"`
	ExpiresAt   types.String   `tfsdk:"expires_at"`
}

type accessFinding struct {
	Username    types.String `tfsdk:"username"`
	MachineName types.String `tfsdk:"machine_name"`
	Rule        types.String `tfsdk:"rule"`
	Message     types.String `tfsdk:"message"`
	Controls    types.String `tfsdk:"controls"`
}

func newAccessReviewDataSource() datasource.DataSource {
	return &accessReviewDataSource{}
}

func (d *accessReviewDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_review"
}

func (d *accessReviewDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	entry := map[string]schema.Attribute{
		"user_id":      schema.StringAttribute{Computed: true},
		"username":     schema.StringAttribute{Computed: true},
		"machine_id":   schema.StringAttribute{Computed: true},
		"machine_name": schema.StringAttribute{Computed: true},
		"access_type":  schema.StringAttribute{Computed: true, Description: `ssh, scp, rdp, vnc, k8s, or "*" from a role.`},
		"remote_users": schema.ListAttribute{Computed: true, ElementType: types.StringType},
		"source":       schema.StringAttribute{Computed: true, Description: `"role:<role>" or "permission:<grant id>".`},
		"expires_at":   schema.StringAttribute{Computed: true},
	}
	finding := map[string]schema.Attribute{
		"username":     schema.StringAttribute{Computed: true},
		"machine_name": schema.StringAttribute{Computed: true},
		"rule":         schema.StringAttribute{Computed: true},
		"message":      schema.StringAttribute{Computed: true},
		"controls":     schema.StringAttribute{Computed: true},
	}
	resp.Schema = schema.Schema{
		Description: "Effective access across machines, checked live against the provider's compliance frameworks. " +
			"Unlike plan-time checks this also sees grants made outside Terraform.",
		Attributes: map[string]schema.Attribute{
			"machine_ids": schema.ListAttribute{
				Description: "Machines to review. Default: every machine.",
				ElementType: types.StringType,
				Optional:    true,
			},
			"generated_at": schema.StringAttribute{Computed: true},
			"frameworks":   schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"entries": schema.ListNestedAttribute{
				Computed:     true,
				NestedObject: schema.NestedAttributeObject{Attributes: entry},
			},
			"findings": schema.ListNestedAttribute{
				Computed:     true,
				NestedObject: schema.NestedAttributeObject{Attributes: finding},
			},
			"compliant": schema.BoolAttribute{Computed: true, Description: "True when there are no findings."},
		},
	}
}

func (d *accessReviewDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *accessReviewDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.data, &resp.Diagnostics) {
		return
	}
	var cfg accessReviewModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	machineIDs := stringValues(cfg.MachineIDs)
	if len(machineIDs) == 0 {
		machines, err := d.data.client.ListMachines(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Cannot list machines", err.Error())
			return
		}
		if len(machines) >= listCap {
			resp.Diagnostics.AddError("Too many machines to review",
				fmt.Sprintf("The gateway lists at most %d machines, so a review of \"every machine\" could miss some and still report compliant. "+
					"Set machine_ids, e.g. split the review by orionbelt_agent resources.", listCap))
			return
		}
		for _, m := range machines {
			machineIDs = append(machineIDs, m.ID)
		}
	}
	sort.Strings(machineIDs)

	var access []sdk.EffectiveAccess
	for _, id := range machineIDs {
		got, err := d.data.client.EffectivePermissions(ctx, "", id)
		if isNotFound(err) {
			resp.Diagnostics.AddError("Cannot read effective access",
				fmt.Sprintf("machine %s: not found. Either the machine was deleted or the gateway is older than the "+
					"effective-access API (/api/v1/admin/permissions/effective, added after v1.4.0); upgrade the gateway.", id))
			return
		}
		if err != nil {
			resp.Diagnostics.AddError("Cannot read effective access", fmt.Sprintf("machine %s: %v", id, err))
			return
		}
		access = append(access, got...)
	}

	now := time.Now().UTC()
	out := accessReviewModel{
		MachineIDs:  cfg.MachineIDs,
		GeneratedAt: types.StringValue(now.Format(time.RFC3339)),
		Frameworks:  stringList(d.data.profile.Frameworks),
		Entries:     []accessEntry{},
		Findings:    []accessFinding{},
	}
	for _, a := range access {
		out.Entries = append(out.Entries, accessEntry{
			UserID:      types.StringValue(a.UserID),
			Username:    types.StringValue(a.Username),
			MachineID:   types.StringValue(a.MachineID),
			MachineName: types.StringValue(a.MachineName),
			AccessType:  types.StringValue(a.AccessType),
			RemoteUsers: stringList(a.RemoteUsers),
			Source:      types.StringValue(a.Source),
			ExpiresAt:   formatExpiry(a.ExpiresAt),
		})
		out.Findings = append(out.Findings, reviewFindings(d.data.profile, a, now)...)
	}
	out.Compliant = types.BoolValue(len(out.Findings) == 0)
	resp.Diagnostics.Append(resp.State.Set(ctx, out)...)
}

// reviewFindings checks grants only. Roles are reviewed through the user
// resources.
func reviewFindings(p compliance.Profile, a sdk.EffectiveAccess, now time.Time) []accessFinding {
	if !strings.HasPrefix(a.Source, "permission:") {
		return nil
	}
	var out []accessFinding
	grant := compliance.Grant{AccessType: a.AccessType, RemoteUsers: a.RemoteUsers, ExpiresAt: a.ExpiresAt}
	for _, v := range p.CheckGrant(grant, now) {
		out = append(out, accessFinding{
			Username:    types.StringValue(a.Username),
			MachineName: types.StringValue(a.MachineName),
			Rule:        types.StringValue(v.Rule),
			Message:     types.StringValue(v.Message),
			Controls:    types.StringValue(v.Controls),
		})
	}
	return out
}
