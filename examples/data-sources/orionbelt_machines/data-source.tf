data "orionbelt_machines" "prod_web" {
  name_prefix = "web-"
  tags        = { env = "prod" }
  active_only = true
}

data "orionbelt_users" "oncall" {
  username_prefix = "oncall-"
}

# One grant per on-call engineer on every production web machine.
resource "orionbelt_machine_access" "prod_web" {
  for_each   = { for m in data.orionbelt_machines.prod_web.machines : m.name => m.id }
  machine_id = each.value

  dynamic "grant" {
    for_each = data.orionbelt_users.oncall.users
    content {
      user_id      = grant.value.id
      access_type  = "ssh"
      remote_users = ["deploy"]
      expires_at   = "2027-01-31T00:00:00Z"
    }
  }
}
