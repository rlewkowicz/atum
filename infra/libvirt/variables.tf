variable "libvirt_uri" {
  description = "Libvirt connection URI."
  type        = string
  default     = "qemu:///system?socket=/run/libvirt/virtqemud-sock"
}

variable "name_prefix" {
  description = "Prefix for local libvirt resources."
  type        = string
  default     = "atum"
}

variable "domain_name" {
  description = "DNS domain attached to the local libvirt network."
  type        = string
  default     = "atum.local"
}

variable "node_count" {
  description = "Number of Kubernetes node VMs."
  type        = number
  default     = 3

  validation {
    condition     = var.node_count > 0 && var.node_count <= 16 && floor(var.node_count) == var.node_count
    error_message = "node_count must be an integer from 1 through 16."
  }
}

variable "node_cpus" {
  description = "vCPU count per Kubernetes node VM."
  type        = number
  default     = 12
}

variable "node_memory_mib" {
  description = "Memory in MiB per Kubernetes node VM."
  type        = number
  default     = 24576
}

variable "load_balancer_cpus" {
  description = "vCPU count for the HAProxy load balancer VM."
  type        = number
  default     = 1
}

variable "load_balancer_memory_mib" {
  description = "Memory in MiB for the HAProxy load balancer VM."
  type        = number
  default     = 1024
}

variable "bastion_cpus" {
  description = "vCPU count for the bastion VM."
  type        = number
  default     = 2
}

variable "bastion_memory_mib" {
  description = "Memory in MiB for the bastion VM."
  type        = number
  default     = 4096
}

variable "bastion_data_disk_size_gib" {
  description = "Persistent seed-service data disk size in GiB for the bastion VM."
  type        = number
  default     = 100

  validation {
    condition     = var.bastion_data_disk_size_gib >= 20 && floor(var.bastion_data_disk_size_gib) == var.bastion_data_disk_size_gib
    error_message = "bastion_data_disk_size_gib must be an integer of at least 20 GiB."
  }
}

variable "disk_size_gib" {
  description = "Root disk size in GiB for every VM."
  type        = number
  default     = 80
}

variable "base_cloud_image_url" {
  description = "Ubuntu cloud image URL used as the VM backing image."
  type        = string
  default     = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
}

variable "ssh_public_key_path" {
  description = "SSH public key authorized for root on local VMs."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "ssh_private_key_path" {
  description = "SSH private key used by Terraform to reconcile bastion seed services."
  type        = string
  default     = "~/.ssh/id_ed25519"
}

variable "seed_archive_path" {
  description = "Absolute path to the lock-bound Atum seed payload; empty disables seed reconciliation for raw Terraform use."
  type        = string
  default     = ""
}

variable "seed_archive_sha256" {
  description = "SHA-256 identity of the Atum seed payload."
  type        = string
  default     = ""
}

variable "seed_forgejo_image" {
  description = "Exact tag loaded from the seed payload for the bastion Forgejo container."
  type        = string
  default     = ""
}

variable "seed_forgejo_username" {
  description = "Administrator username supplied from Atum's typed secret source."
  type        = string
  sensitive   = true
  default     = ""
}

variable "seed_forgejo_admin_password" {
  description = "Administrator password supplied from Atum's typed secret source."
  type        = string
  sensitive   = true
  default     = ""
}

variable "seed_forgejo_url" {
  description = "Private HTTP origin for the bastion Forgejo service."
  type        = string
  default     = "http://10.77.0.9:3000"
}

variable "seed_harbor_version" {
  description = "Exact Harbor release loaded from the seed payload."
  type        = string
  default     = ""
}

variable "seed_harbor_url" {
  description = "Private HTTP origin for the bastion Harbor service."
  type        = string
  default     = "http://10.77.0.9:32443"
}

variable "seed_harbor_admin_password" {
  description = "Initial Harbor administrator password supplied from Atum's typed secret source."
  type        = string
  sensitive   = true
  default     = ""
}

variable "seed_harbor_secret_key" {
  description = "Stable Harbor secret used to derive its internal database credential."
  type        = string
  sensitive   = true
  default     = ""
}

variable "network_name" {
  description = "Name of the local libvirt NAT network."
  type        = string
  default     = "atum"
}

variable "network_cidr" {
  description = "CIDR for the local libvirt NAT network."
  type        = string
  default     = "10.77.0.0/24"

  validation {
    condition     = can(regex("\\.", cidrhost(var.network_cidr, 1)))
    error_message = "network_cidr must be an IPv4 CIDR."
  }
}

variable "node_ips" {
  description = "Deterministic DHCP IPv4 addresses assigned to Kubernetes node VMs."
  type        = list(string)
  default     = ["10.77.0.11", "10.77.0.12", "10.77.0.13"]

  validation {
    condition     = length(var.node_ips) > 0 && length(distinct(var.node_ips)) == length(var.node_ips) && alltrue([for address in var.node_ips : can(cidrhost("${address}/32", 0)) && strcontains(address, ".")])
    error_message = "node_ips must contain unique IPv4 addresses."
  }
}

variable "load_balancer_ip" {
  description = "Deterministic DHCP IPv4 address assigned to the HAProxy load balancer VM."
  type        = string
  default     = "10.77.0.10"

  validation {
    condition     = can(cidrhost("${var.load_balancer_ip}/32", 0)) && strcontains(var.load_balancer_ip, ".")
    error_message = "load_balancer_ip must be an IPv4 address."
  }
}

variable "bastion_ip" {
  description = "Deterministic DHCP IPv4 address assigned to the bastion VM."
  type        = string
  default     = "10.77.0.9"

  validation {
    condition     = can(cidrhost("${var.bastion_ip}/32", 0)) && strcontains(var.bastion_ip, ".")
    error_message = "bastion_ip must be an IPv4 address."
  }
}

variable "platform_domain" {
  description = "Local application DNS domain served by the libvirt dnsmasq instance."
  type        = string
  default     = "atum.test"

  validation {
    condition     = length(var.platform_domain) <= 253 && can(regex("^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", var.platform_domain))
    error_message = "platform_domain must be a lowercase fully qualified DNS name with valid labels."
  }
}

variable "dns_server" {
  description = "IPv4 address of the libvirt network gateway and dnsmasq service."
  type        = string
  default     = "10.77.0.1"

  validation {
    condition     = can(cidrhost("${var.dns_server}/32", 0)) && strcontains(var.dns_server, ".")
    error_message = "dns_server must be an IPv4 address."
  }
}

variable "public_ingress_vip" {
  description = "Static kube-vip address for the public Istio gateway."
  type        = string
  default     = "10.77.0.20"

  validation {
    condition     = can(cidrhost("${var.public_ingress_vip}/32", 0)) && strcontains(var.public_ingress_vip, ".")
    error_message = "public_ingress_vip must be an IPv4 address."
  }
}

variable "passthrough_ingress_vip" {
  description = "Static kube-vip address for the TLS-passthrough Istio gateway."
  type        = string
  default     = "10.77.0.21"

  validation {
    condition     = can(cidrhost("${var.passthrough_ingress_vip}/32", 0)) && strcontains(var.passthrough_ingress_vip, ".")
    error_message = "passthrough_ingress_vip must be an IPv4 address."
  }
}

variable "load_balancer_range" {
  description = "Inclusive IPv4 range allocated to dynamic local LoadBalancer Services."
  type = object({
    start = string
    end   = string
  })
  default = {
    start = "10.77.0.22"
    end   = "10.77.0.39"
  }

  validation {
    condition = alltrue([
      for address in [var.load_balancer_range.start, var.load_balancer_range.end] :
      can(cidrhost("${address}/32", 0)) && strcontains(address, ".")
    ])
    error_message = "load_balancer_range start and end must be IPv4 addresses."
  }

  validation {
    condition = try(
      sum([for index, octet in split(".", var.load_balancer_range.start) : tonumber(octet) * pow(256, 3 - index)]) <=
      sum([for index, octet in split(".", var.load_balancer_range.end) : tonumber(octet) * pow(256, 3 - index)]),
      false,
    )
    error_message = "load_balancer_range start must not follow its end."
  }
}

variable "passthrough_hosts" {
  description = "DNS labels routed exactly to the TLS-passthrough Istio gateway."
  type        = list(string)
  default     = ["keycloak"]

  validation {
    condition = length(distinct(var.passthrough_hosts)) == length(var.passthrough_hosts) && alltrue([
      for label in var.passthrough_hosts :
      length(label) <= 63 && can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label))
    ])
    error_message = "passthrough_hosts must contain unique lowercase DNS labels."
  }
}

variable "storage_pool" {
  description = "Libvirt storage pool for VM disks and cloud-init ISOs."
  type        = string
  default     = "default"
}
