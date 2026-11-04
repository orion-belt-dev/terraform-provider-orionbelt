terraform {
  required_providers {
    orionbelt = {
      source = "orion-belt-dev/orionbelt"
    }
  }
}

# The API key is read from ORIONBELT_API_KEY when api_key is not set.
provider "orionbelt" {
  url = "https://orion.example.com"

  compliance {
    frameworks         = ["soc2", "pci-dss-4"]
    max_grant_duration = "720h"
  }
}
