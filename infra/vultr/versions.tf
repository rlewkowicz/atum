terraform {
  required_version = ">= 1.6.0"

  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = ">= 2.23.0, < 3.0.0"
    }
  }
}
