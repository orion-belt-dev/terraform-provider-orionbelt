# terraform query -generate-config-out=users.tf
list "orionbelt_user" "operators" {
  provider = orionbelt

  config {
    role = "operator"
  }
}
