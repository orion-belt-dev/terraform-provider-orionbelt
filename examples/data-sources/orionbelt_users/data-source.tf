data "orionbelt_users" "operators" {
  role = "operator"
}

output "operators_without_mfa" {
  value = [for u in data.orionbelt_users.operators.users : u.username if !u.mfa_enabled]
}
