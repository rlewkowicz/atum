terraform {
  required_version = ">= 1.5.0"

  required_providers {
    # v0.9.8 reconciles running=true drift after retained teardown.
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.9.8"
    }
  }
}

provider "libvirt" {
  uri = var.libvirt_uri
}
