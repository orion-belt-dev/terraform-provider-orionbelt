terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.1"
    }
    orionbelt = {
      source = "orion-belt-dev/orionbelt"
    }
  }
}

provider "aws" {
  region = var.region
}

provider "orionbelt" {
  url = var.gateway_url

  compliance {
    frameworks = ["soc2", "pci-dss-4"]
  }
}
