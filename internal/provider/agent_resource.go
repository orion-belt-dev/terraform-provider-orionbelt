package provider

import (
	"context"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"

	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/agentconfig"
	"github.com/orion-belt-dev/terraform-provider-orionbelt/internal/compliance"
)

var (
	_ resource.ResourceWithConfigure   = (*agentResource)(nil)
	_ resource.ResourceWithImportState = (*agentResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*agentResource)(nil)
)

type agentResource struct {
	data *providerData
}

type agentModel struct {
	ID                types.String            `tfsdk:"id"`
	Name              types.String            `tfsdk:"name"`
	Hostname          types.String            `tfsdk:"hostname"`
	Port              types.Int64             `tfsdk:"port"`
	Tags              map[string]types.String `tfsdk:"tags"`
	PublicKey         types.String            `tfsdk:"public_key"`
	GatewayHost       types.String            `tfsdk:"gateway_host"`
	GatewayPort       types.Int64             `tfsdk:"gateway_port"`
	GatewayHostKey    types.String            `tfsdk:"gateway_host_key"`
	ArchiveOnDestroy  types.Bool              `tfsdk:"archive_on_destroy"`
	InstallVersion    types.String            `tfsdk:"install_version"`
	PrivateKeyCommand types.String            `tfsdk:"private_key_command"`
	HostCertificate   types.String            `tfsdk:"host_certificate"`
	HostCAPublicKey   types.String            `tfsdk:"host_ca_public_key"`
	AgentYAML         types.String            `tfsdk:"agent_yaml"`
	CloudInit         types.String            `tfsdk:"cloud_init"`
}

var agentNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func newAgentResource() resource.Resource {
	return &agentResource{}
}

func (r *agentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent"
}

func (r *agentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		Description: "Registers an agent (a machine reached through a reverse tunnel) and renders its configuration. " +
			"Only the public key is sent; the private key stays on the host or in your secret store.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "Machine ID.",
				Computed:      true,
				PlanModifiers: keep,
			},
			"name": schema.StringAttribute{
				Description:   "Agent and machine name. Changing it replaces the agent.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 64),
					stringvalidator.RegexMatches(agentNamePattern, "must contain only letters, digits, dot, dash and underscore"),
				},
			},
			"hostname": schema.StringAttribute{
				Description:   "Address the agent connects to locally. Defaults to name.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: keep,
			},
			"port": schema.Int64Attribute{
				Description: "Local SSH port on the target. Default 22.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(22),
				Validators:  []validator.Int64{int64validator.Between(1, 65535)},
			},
			"tags": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"public_key": schema.StringAttribute{
				Description:   "Agent's SSH public key in authorized_keys format. Changing it replaces the agent.",
				Required:      true,
				PlanModifiers: []planmodifier.String{replaceUnlessImported()},
			},
			"gateway_host": schema.StringAttribute{
				Description:   "Gateway SSH host agents dial. Defaults to the gateway's advertised public SSH host.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: keep,
			},
			"gateway_port": schema.Int64Attribute{
				Description:   "Gateway SSH port agents dial. Defaults to the advertised port.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
				Validators:    []validator.Int64{int64validator.Between(1, 65535)},
			},
			"gateway_host_key": schema.StringAttribute{
				Description: "Pins the gateway's SSH host key (authorized_keys format) when it has no host CA.",
				Optional:    true,
			},
			"archive_on_destroy": schema.BoolAttribute{
				Description: "Deactivate instead of deleting on destroy. Deleting also deletes the machine's session recordings. Default true.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"install_version": schema.StringAttribute{
				Description: "Agent release cloud-init installs, e.g. v1.4.0. Default: latest.",
				Optional:    true,
			},
			"private_key_command": schema.StringAttribute{
				Sensitive: true,
				Description: "Shell command that prints the agent's private key on the host at first boot, " +
					"e.g. reading AWS Secrets Manager. Required for cloud_init.",
				Optional: true,
			},
			"host_certificate": schema.StringAttribute{
				Description:   "Host certificate the gateway issued for this agent, when it runs an SSH CA.",
				Computed:      true,
				PlanModifiers: keep,
			},
			"host_ca_public_key": schema.StringAttribute{
				Description:   "Gateway host CA the agent trusts.",
				Computed:      true,
				PlanModifiers: keep,
			},
			"agent_yaml": schema.StringAttribute{
				Description: "Contents of /etc/orion-belt/agent.yaml.",
				Computed:    true,
			},
			"cloud_init": schema.StringAttribute{
				Description: "#cloud-config user data that installs and starts the agent. Null without private_key_command. " +
					"Sensitive because it embeds private_key_command.",
				Computed:  true,
				Sensitive: true,
			},
		},
	}
}

func (r *agentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = providerDataFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *agentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.data == nil {
		return
	}
	var plan agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.PublicKey.IsUnknown() {
		validatePublicKey(&resp.Diagnostics, plan.PublicKey.ValueString())
	}
	if !plan.GatewayHostKey.IsNull() && !plan.GatewayHostKey.IsUnknown() {
		validateKeyAt(&resp.Diagnostics, path.Root("gateway_host_key"), plan.GatewayHostKey.ValueString())
	}

	if plan.ArchiveOnDestroy.IsUnknown() || plan.GatewayHostKey.IsUnknown() {
		return
	}
	r.checkCompliance(ctx, plan, &resp.Diagnostics)
}

// checkCompliance runs the agent rules. The host CA rule needs the gateway's
// answer, so it is checked only once a client exists; Create and Update call
// this again before touching the gateway.
func (r *agentResource) checkCompliance(ctx context.Context, m agentModel, diags *diag.Diagnostics) {
	facts := compliance.Agent{
		ArchiveOnDestroy: archiveOnDestroy(m),
		GatewayHostKey:   m.GatewayHostKey.ValueString(),
	}
	if r.data.client != nil && r.data.profile.RequireHostCA {
		ca, err := r.data.client.GetTrustedCA(ctx)
		if err != nil {
			diags.AddError("Cannot read the gateway's SSH CA", err.Error())
			return
		}
		facts.HostCAKnown = true
		facts.HostCAPublicKey = ca.HostCA
	}
	addViolations(diags, path.Empty(), r.data.profile.CheckAgent(facts))
}

// archiveOnDestroy treats a missing value (e.g. right after import) as
// true, the safe choice.
func archiveOnDestroy(m agentModel) bool {
	return m.ArchiveOnDestroy.IsNull() || m.ArchiveOnDestroy.IsUnknown() || m.ArchiveOnDestroy.ValueBool()
}

func (r *agentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Hostname.IsUnknown() || plan.Hostname.IsNull() {
		plan.Hostname = plan.Name
	}
	r.fillGatewayDefaults(ctx, &plan, &resp.Diagnostics)
	r.checkCompliance(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	reg, err := r.data.client.RegisterAgent(ctx, sdk.RegisterAgentRequest{
		Name:      plan.Name.ValueString(),
		Hostname:  plan.Hostname.ValueString(),
		Port:      int(plan.Port.ValueInt64()),
		PublicKey: strings.TrimSpace(plan.PublicKey.ValueString()),
		Tags:      stringMap(plan.Tags),
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot register agent", err.Error())
		return
	}
	plan.ID = types.StringValue(reg.MachineID)
	plan.HostCertificate = types.StringValue(strings.TrimSpace(reg.HostCertificate))
	plan.HostCAPublicKey = types.StringValue(strings.TrimSpace(reg.HostCAPublicKey))

	// Save the ID before rendering so a rendering failure cannot orphan the
	// machine; agent_yaml and cloud_init are still unknown here.
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)

	r.render(&plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *agentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state agentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	machine, err := r.data.client.GetMachine(ctx, state.ID.ValueString())
	if isNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Cannot read agent", err.Error())
		return
	}
	state.Name = types.StringValue(machine.Name)
	state.Hostname = types.StringValue(machine.Hostname)
	state.Port = types.Int64Value(int64(machine.Port))
	// An empty tags map in config reads back as no tags; keep it so the
	// plan does not show tags = {} forever.
	if len(machine.Tags) > 0 || len(state.Tags) > 0 {
		state.Tags = stringMapValue(machine.Tags)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *agentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var plan, state agentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Hostname.IsUnknown() || plan.Hostname.IsNull() {
		plan.Hostname = plan.Name
	}
	r.fillGatewayDefaults(ctx, &plan, &resp.Diagnostics)
	r.checkCompliance(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.HostCAPublicKey.IsNull() || plan.HostCAPublicKey.IsUnknown() {
		// Imported agents have no registration response to read it from.
		plan.HostCAPublicKey = types.StringValue("")
		if ca, err := r.data.client.GetTrustedCA(ctx); err == nil {
			plan.HostCAPublicKey = types.StringValue(strings.TrimSpace(ca.HostCA))
		}
	}
	if plan.HostCertificate.IsNull() || plan.HostCertificate.IsUnknown() {
		plan.HostCertificate = types.StringValue("")
	}

	hostname := plan.Hostname.ValueString()
	port := int(plan.Port.ValueInt64())
	tags := stringMap(plan.Tags)
	if tags == nil {
		tags = map[string]string{}
	}
	_, err := r.data.client.UpdateMachine(ctx, state.ID.ValueString(), sdk.UpdateMachineRequest{
		Hostname: &hostname,
		Port:     &port,
		Tags:     &tags,
	})
	if err != nil {
		resp.Diagnostics.AddError("Cannot update agent", err.Error())
		return
	}

	r.render(&plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *agentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.data, &resp.Diagnostics) {
		return
	}
	var state agentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if archiveOnDestroy(state) {
		r.archive(ctx, state, &resp.Diagnostics)
		return
	}
	// Re-check at destroy time: a framework may forbid deleting evidence.
	addViolations(&resp.Diagnostics, path.Empty(),
		r.data.profile.CheckAgent(compliance.Agent{ArchiveOnDestroy: false}))
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.data.client.DeleteMachine(ctx, state.ID.ValueString(), false)
	if err != nil && !isNotFound(err) {
		resp.Diagnostics.AddError("Cannot delete agent", err.Error())
	}
}

// archive deactivates the machine and renames it so its name is free for a
// replacement agent (e.g. after a key rotation).
func (r *agentResource) archive(ctx context.Context, state agentModel, diags *diag.Diagnostics) {
	id := state.ID.ValueString()
	machine, err := r.data.client.GetMachine(ctx, id)
	if isNotFound(err) {
		return
	}
	if err != nil {
		diags.AddError("Cannot read agent before archiving", err.Error())
		return
	}

	archivedName := state.Name.ValueString() + "-archived-" + id
	_, err = r.data.client.UpdateMachine(ctx, id, sdk.UpdateMachineRequest{Name: &archivedName})
	if err != nil {
		diags.AddError("Cannot rename agent before archiving", err.Error())
		return
	}
	err = r.data.client.DeleteMachine(ctx, id, true)
	if err != nil && !isNotFound(err) {
		diags.AddError("Cannot archive agent", err.Error())
		return
	}

	// Without an SSH CA an agent is identified by a user named after it.
	// Deleting that user revokes the retired key and frees the name. Only
	// the synthetic agent user is removed, never a person an admin linked.
	if machine.AgentID == "" {
		return
	}
	agentUser, err := r.data.client.GetUser(ctx, machine.AgentID)
	if isNotFound(err) {
		return
	}
	if err != nil {
		diags.AddError("Cannot read archived agent's identity", err.Error())
		return
	}
	if agentUser.Username != state.Name.ValueString() || !strings.HasSuffix(agentUser.Email, "@agent.orion-belt") {
		return
	}
	err = r.data.client.DeleteUser(ctx, machine.AgentID)
	if err != nil && !isNotFound(err) {
		diags.AddError("Cannot remove archived agent's identity", err.Error())
	}
}

func (r *agentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("archive_on_destroy"), true)...)
}

func (r *agentResource) fillGatewayDefaults(ctx context.Context, m *agentModel, diags *diag.Diagnostics) {
	needHost := m.GatewayHost.IsUnknown() || m.GatewayHost.IsNull()
	needPort := m.GatewayPort.IsUnknown() || m.GatewayPort.IsNull()
	if !needHost && !needPort {
		return
	}
	info, err := r.data.client.GetGatewayInfo(ctx)
	if err != nil {
		diags.AddError("Cannot read gateway info", "Set gateway_host and gateway_port, or check the API key: "+err.Error())
		return
	}
	if needHost {
		host := info.PublicSSHHost
		if host == "" {
			host = info.SSHHost
		}
		m.GatewayHost = types.StringValue(host)
	}
	if needPort {
		port := info.PublicSSHPort
		if port == 0 {
			port = info.SSHPort
		}
		m.GatewayPort = types.Int64Value(int64(port))
	}
}

func (r *agentResource) render(m *agentModel, diags *diag.Diagnostics) {
	a := agentconfig.Agent{
		Name:            m.Name.ValueString(),
		Tags:            stringMap(m.Tags),
		GatewayHost:     m.GatewayHost.ValueString(),
		GatewayPort:     int(m.GatewayPort.ValueInt64()),
		HostCertificate: m.HostCertificate.ValueString(),
		HostCAPublicKey: m.HostCAPublicKey.ValueString(),
		GatewayHostKey:  m.GatewayHostKey.ValueString(),
	}

	agentYAML, err := agentconfig.AgentYAML(a)
	if err != nil {
		diags.AddError("Cannot render agent.yaml", err.Error())
		return
	}
	m.AgentYAML = types.StringValue(agentYAML)

	m.CloudInit = types.StringNull()
	if m.PrivateKeyCommand.IsNull() {
		return
	}
	cloudInit, err := agentconfig.CloudInit(a, agentconfig.Install{
		Version:           m.InstallVersion.ValueString(),
		PrivateKeyCommand: m.PrivateKeyCommand.ValueString(),
	})
	if err != nil {
		diags.AddError("Cannot render cloud-init", err.Error())
		return
	}
	m.CloudInit = types.StringValue(cloudInit)
}

func validatePublicKey(diags *diag.Diagnostics, key string) {
	validateKeyAt(diags, path.Root("public_key"), key)
	if diags.HasError() {
		return
	}
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(key))
	if _, isCert := pub.(*ssh.Certificate); isCert {
		diags.AddAttributeError(path.Root("public_key"), "Invalid public key", "Give the plain public key, not a certificate.")
	}
}

func validateKeyAt(diags *diag.Diagnostics, at path.Path, key string) {
	if strings.Contains(key, "PRIVATE KEY") {
		diags.AddAttributeError(at, "Private key given", "This attribute takes a public key. Never put a private key in Terraform configuration.")
		return
	}
	if strings.ContainsAny(strings.TrimSpace(key), "\r\n") {
		diags.AddAttributeError(at, "Invalid public key", "Give exactly one key on one line.")
		return
	}
	_, _, options, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		diags.AddAttributeError(at, "Invalid public key", "Expected authorized_keys format, e.g. ssh-ed25519 AAAA...: "+err.Error())
		return
	}
	if len(options) > 0 {
		diags.AddAttributeError(at, "Invalid public key", "Give the bare key without authorized_keys options.")
	}
}

// replaceUnlessImported forces replacement when the key changes, except
// right after import, when the key is not yet in state.
func replaceUnlessImported() planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
			resp.RequiresReplace = !req.StateValue.IsNull()
		},
		"Changing the key replaces the agent.",
		"Changing the key replaces the agent.",
	)
}
