# terraform query -generate-config-out=machine_access.tf
# Importing a result adopts every standing grant on that machine; grants
# removed from the generated block are revoked on the next apply.
list "orionbelt_machine_access" "prod" {
  provider = orionbelt

  config {
    tags = { env = "prod" }
  }
}
