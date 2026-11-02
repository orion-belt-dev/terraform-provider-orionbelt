terraform {
  required_providers {
    orionbelt = {
      source = "orion-belt-dev/orionbelt"
    }
  }
}

provider "orionbelt" {
  url     = "https://gateway.invalid"
  api_key = "unused"

  compliance {
    frameworks = ["pci-dss-4"]
  }
}

resource "orionbelt_user" "shared" {
  username = "admin"
  email    = "ops@example.com"
}

resource "orionbelt_permission" "root_forever" {
  user_id     = "user-1"
  machine_id  = "machine-1"
  access_type = "ssh"

  remote_users = ["root"]
}
