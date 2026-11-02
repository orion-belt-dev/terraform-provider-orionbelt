package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
)

const fakeAPIKey = "test-key"

// fakeGateway is an in-memory stand-in for the Orion Belt API, covering the
// endpoints the provider calls. It is not a full model of the server: it
// checks the API key, stores what it is sent, and records deletes.
type fakeGateway struct {
	t      *testing.T
	server *httptest.Server

	mu          sync.Mutex
	nextID      int
	users       map[string]*sdk.User
	machines    map[string]*sdk.Machine
	permissions map[string]*sdk.Permission
	riskPolicy  sdk.RiskPolicy
	hostCA      string
	deletes     []string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{
		t:           t,
		users:       map[string]*sdk.User{},
		machines:    map[string]*sdk.Machine{},
		permissions: map[string]*sdk.Permission{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/gateway-info", g.gatewayInfo)
	mux.HandleFunc("GET /api/v1/ssh-cert/ca", g.authed(g.trustedCA))

	mux.HandleFunc("GET /api/v1/users", g.authed(g.listUsers))
	mux.HandleFunc("GET /api/v1/users/{id}", g.authed(g.getUser))
	mux.HandleFunc("POST /api/v1/admin/users", g.authed(g.createUser))
	mux.HandleFunc("PUT /api/v1/admin/users/{id}", g.authed(g.updateUser))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}", g.authed(g.deleteUser))

	mux.HandleFunc("POST /api/v1/public/register/agent", g.authed(g.registerAgent))
	mux.HandleFunc("GET /api/v1/machines", g.authed(g.listMachines))
	mux.HandleFunc("GET /api/v1/machines/{id}", g.authed(g.getMachine))
	mux.HandleFunc("PUT /api/v1/admin/machines/{id}", g.authed(g.updateMachine))
	mux.HandleFunc("DELETE /api/v1/admin/machines/{id}", g.authed(g.deleteMachine))

	mux.HandleFunc("GET /api/v1/permissions/machine/{id}", g.authed(g.machinePermissions))
	mux.HandleFunc("POST /api/v1/admin/permissions", g.authed(g.grantPermission))
	mux.HandleFunc("PATCH /api/v1/admin/permissions/{id}", g.authed(g.updatePermission))
	mux.HandleFunc("DELETE /api/v1/admin/permissions/{id}", g.authed(g.revokePermission))
	mux.HandleFunc("GET /api/v1/admin/permissions/effective", g.authed(g.effective))

	mux.HandleFunc("GET /api/v1/admin/risk-policy", g.authed(g.getRiskPolicy))
	mux.HandleFunc("PUT /api/v1/admin/risk-policy", g.authed(g.putRiskPolicy))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fake gateway: unexpected %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})

	g.server = httptest.NewServer(mux)
	t.Cleanup(g.server.Close)
	return g
}

func (g *fakeGateway) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != fakeAPIKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		h(w, r)
	}
}

func (g *fakeGateway) id(prefix string) string {
	g.nextID++
	return fmt.Sprintf("%s-%d", prefix, g.nextID)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return false
	}
	return true
}

func (g *fakeGateway) gatewayInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, sdk.GatewayInfo{PublicURL: g.server.URL, SSHHost: "gw.internal", SSHPort: 2222, PublicSSHHost: "gw.example.com", PublicSSHPort: 2222})
}

func (g *fakeGateway) trustedCA(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, sdk.TrustedCA{Enabled: g.hostCA != "", HostCA: g.hostCA})
}

func (g *fakeGateway) listUsers(w http.ResponseWriter, _ *http.Request) {
	out := []sdk.User{}
	for _, u := range g.users {
		out = append(out, *u)
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *fakeGateway) getUser(w http.ResponseWriter, r *http.Request) {
	u, ok := g.users[r.PathValue("id")]
	if !ok {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (g *fakeGateway) createUser(w http.ResponseWriter, r *http.Request) {
	var req sdk.CreateUserRequest
	if !decode(w, r, &req) {
		return
	}
	u := &sdk.User{ID: g.id("user"), Username: req.Username, Email: req.Email, PublicKey: req.PublicKey, Role: req.Role, IsAdmin: req.IsAdmin}
	g.users[u.ID] = u
	writeJSON(w, http.StatusCreated, u)
}

func (g *fakeGateway) updateUser(w http.ResponseWriter, r *http.Request) {
	u, ok := g.users[r.PathValue("id")]
	if !ok {
		notFound(w)
		return
	}
	var req sdk.UpdateUserRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.Role != nil {
		u.Role = *req.Role
	}
	if req.IsAdmin != nil {
		u.IsAdmin = *req.IsAdmin
	}
	if req.PublicKey != nil {
		u.PublicKey = *req.PublicKey
	}
	writeJSON(w, http.StatusOK, u)
}

func (g *fakeGateway) deleteUser(w http.ResponseWriter, r *http.Request) {
	delete(g.users, r.PathValue("id"))
	g.deletes = append(g.deletes, "user "+r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

func (g *fakeGateway) registerAgent(w http.ResponseWriter, r *http.Request) {
	var req sdk.RegisterAgentRequest
	if !decode(w, r, &req) {
		return
	}
	for _, m := range g.machines {
		if m.Name == req.Name {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "agent already registered"})
			return
		}
	}
	m := &sdk.Machine{ID: g.id("machine"), Name: req.Name, Hostname: req.Hostname, Port: req.Port, Tags: req.Tags, IsActive: true}
	resp := sdk.RegisterAgentResponse{}
	if g.hostCA == "" {
		for _, u := range g.users {
			if u.Username == req.Name {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to register agent"})
				return
			}
		}
		agentUser := &sdk.User{ID: g.id("user"), Username: req.Name, Email: req.Name + "@agent.orion-belt", PublicKey: req.PublicKey}
		g.users[agentUser.ID] = agentUser
		m.AgentID = agentUser.ID
		resp.UserID = agentUser.ID
	}
	g.machines[m.ID] = m
	resp.MachineID = m.ID
	if g.hostCA != "" {
		resp.HostCertificate = "ssh-ed25519-cert-v01@openssh.com AAAAcert " + m.ID
		resp.HostCAPublicKey = g.hostCA
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (g *fakeGateway) listMachines(w http.ResponseWriter, _ *http.Request) {
	out := []sdk.Machine{}
	for _, m := range g.machines {
		out = append(out, *m)
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *fakeGateway) getMachine(w http.ResponseWriter, r *http.Request) {
	m, ok := g.machines[r.PathValue("id")]
	if !ok {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (g *fakeGateway) updateMachine(w http.ResponseWriter, r *http.Request) {
	m, ok := g.machines[r.PathValue("id")]
	if !ok {
		notFound(w)
		return
	}
	var req sdk.UpdateMachineRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name != nil {
		for _, other := range g.machines {
			if other.Name == *req.Name && other.ID != m.ID {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "machine name already exists"})
				return
			}
		}
		m.Name = *req.Name
	}
	if req.Hostname != nil {
		m.Hostname = *req.Hostname
	}
	if req.Port != nil {
		m.Port = *req.Port
	}
	if req.Tags != nil {
		m.Tags = *req.Tags
	}
	writeJSON(w, http.StatusOK, m)
}

func (g *fakeGateway) deleteMachine(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := g.machines[id]; !ok {
		notFound(w)
		return
	}
	if r.URL.Query().Get("archive") == "true" {
		g.machines[id].IsActive = false
		g.deletes = append(g.deletes, "archive machine "+id)
	} else {
		delete(g.machines, id)
		g.deletes = append(g.deletes, "delete machine "+id)
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "ok"})
}

func (g *fakeGateway) machinePermissions(w http.ResponseWriter, r *http.Request) {
	out := []sdk.Permission{}
	for _, p := range g.permissions {
		if p.MachineID == r.PathValue("id") {
			out = append(out, *p)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type grantBody struct {
	UserID      string   `json:"user_id"`
	MachineID   string   `json:"machine_id"`
	AccessType  string   `json:"access_type"`
	RemoteUsers []string `json:"remote_users"`
	ExpiresAt   *string  `json:"expires_at"`
	DurationSec *int     `json:"duration_seconds"`
}

// applyExpiry mirrors the server: POST turns expires_at into a duration
// from now (so the stored time drifts by the request latency), PATCH stores
// expires_at as given, and duration_seconds <= 0 clears the expiry.
func applyExpiry(p *sdk.Permission, body grantBody, isPatch bool) error {
	if body.DurationSec != nil {
		p.ExpiresAt = nil
		if *body.DurationSec > 0 {
			t := time.Now().Add(time.Duration(*body.DurationSec) * time.Second).UTC()
			p.ExpiresAt = &t
		}
		return nil
	}
	if body.ExpiresAt == nil || *body.ExpiresAt == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *body.ExpiresAt)
	if err != nil {
		return err
	}
	if !isPatch {
		t = time.Now().Add(time.Until(t) + 3*time.Millisecond)
	}
	t = t.UTC()
	p.ExpiresAt = &t
	return nil
}

func validateTargets(p *sdk.Permission) error {
	switch p.AccessType {
	case "ssh", "scp", "both":
		if len(p.RemoteUsers) == 0 {
			return fmt.Errorf("remote_users is required")
		}
	}
	return nil
}

func (g *fakeGateway) grantPermission(w http.ResponseWriter, r *http.Request) {
	var body grantBody
	if !decode(w, r, &body) {
		return
	}
	p := &sdk.Permission{
		ID:          g.id("perm"),
		UserID:      body.UserID,
		MachineID:   body.MachineID,
		AccessType:  body.AccessType,
		RemoteUsers: body.RemoteUsers,
		GrantedBy:   "terraform",
		GrantedAt:   time.Now().UTC(),
	}
	if err := applyExpiry(p, body, false); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validateTargets(p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	g.permissions[p.ID] = p
	writeJSON(w, http.StatusCreated, p)
}

func (g *fakeGateway) updatePermission(w http.ResponseWriter, r *http.Request) {
	p, ok := g.permissions[r.PathValue("id")]
	if !ok {
		notFound(w)
		return
	}
	var body grantBody
	if !decode(w, r, &body) {
		return
	}
	updated := *p
	if body.RemoteUsers != nil {
		updated.RemoteUsers = body.RemoteUsers
	}
	if err := applyExpiry(&updated, body, true); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validateTargets(&updated); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	updated.GrantedBy = "terraform-update"
	updated.GrantedAt = time.Now().UTC().Add(time.Second)
	*p = updated
	writeJSON(w, http.StatusOK, p)
}

func (g *fakeGateway) revokePermission(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.permissions[r.PathValue("id")]; !ok {
		notFound(w)
		return
	}
	delete(g.permissions, r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"message": "revoked"})
}

func (g *fakeGateway) effective(w http.ResponseWriter, r *http.Request) {
	machineID := r.URL.Query().Get("machine_id")
	out := []sdk.EffectiveAccess{}
	for _, p := range g.permissions {
		if p.MachineID != machineID {
			continue
		}
		username := ""
		if u, ok := g.users[p.UserID]; ok {
			username = u.Username
		}
		types := []string{p.AccessType}
		if p.AccessType == "both" {
			types = []string{"ssh", "scp"}
		}
		for _, t := range types {
			out = append(out, sdk.EffectiveAccess{
				UserID:      p.UserID,
				Username:    username,
				MachineID:   p.MachineID,
				MachineName: g.machines[p.MachineID].Name,
				AccessType:  t,
				RemoteUsers: p.RemoteUsers,
				Source:      "permission:" + p.ID,
				ExpiresAt:   p.ExpiresAt,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *fakeGateway) getRiskPolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, g.riskPolicy)
}

func (g *fakeGateway) putRiskPolicy(w http.ResponseWriter, r *http.Request) {
	var p sdk.RiskPolicy
	if !decode(w, r, &p) {
		return
	}
	if err := p.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	p.UpdatedAt = time.Now().UTC()
	g.riskPolicy = p
	writeJSON(w, http.StatusOK, p)
}

// addGrant inserts a grant directly, as if an admin used the console.
func (g *fakeGateway) addGrant(userID, machineID, accessType string, remoteUsers ...string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := &sdk.Permission{ID: g.id("perm"), UserID: userID, MachineID: machineID, AccessType: accessType, RemoteUsers: remoteUsers, GrantedBy: "console", GrantedAt: time.Now().UTC()}
	g.permissions[p.ID] = p
	return p.ID
}

// addMachine inserts a machine directly, as if registered by the console.
func (g *fakeGateway) addMachine(name string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := &sdk.Machine{ID: g.id("machine"), Name: name, Hostname: name, Port: 22, IsActive: true}
	g.machines[m.ID] = m
	return m.ID
}

func (g *fakeGateway) permissionCount(machineID string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, p := range g.permissions {
		if p.MachineID == machineID {
			n++
		}
	}
	return n
}

func (g *fakeGateway) deleteLog() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.deletes...)
}
