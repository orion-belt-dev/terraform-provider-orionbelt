resource "orionbelt_permission" "deploy" {
  user_id      = orionbelt_user.engineer.id
  machine_id   = data.orionbelt_machine.web.id
  access_type  = "ssh"
  remote_users = ["deploy"]
  expires_at   = "2027-01-31T00:00:00Z"
}
