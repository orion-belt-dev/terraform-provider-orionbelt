# Manages every grant on the machine. Grants not listed here are revoked.
resource "orionbelt_machine_access" "web" {
  machine_id = orionbelt_agent.web.id

  grant {
    user_id      = orionbelt_user.engineer.id
    access_type  = "ssh"
    remote_users = ["deploy"]
    expires_at   = "2027-01-31T00:00:00Z"
  }
}
