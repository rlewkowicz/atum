variable "enabled" {
  description = "Whether to create module resources."
  type        = bool
  default     = true
}

variable "namespace" {
  description = "Top-level namespace used in generated resource names and propagated tags."
  type        = string
  default     = "atum"
}

variable "tenant" {
  description = "Optional tenant or business unit used in generated resource names and propagated tags."
  type        = string
  default     = null
}

variable "environment" {
  description = "Optional environment label used in generated resource names and propagated tags."
  type        = string
  default     = null
}

variable "stage" {
  description = "Deployment stage used in generated resource names and propagated tags."
  type        = string
  default     = "prod"
}

variable "name" {
  description = "Application or service name used in generated resource names and propagated tags."
  type        = string
  default     = "atum"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name))
    error_message = "name must start with a lowercase letter and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "attributes" {
  description = "Additional ordered attributes appended to the generated resource name."
  type        = list(string)
  default     = []
}

variable "delimiter" {
  description = "Delimiter used between generated name segments."
  type        = string
  default     = "-"
}

variable "label_order" {
  description = "Ordered label keys used to generate the module ID."
  type        = list(string)
  default     = ["namespace", "environment", "stage", "name", "attributes"]

  validation {
    condition = length(setsubtract(
      toset(var.label_order),
      toset(["namespace", "tenant", "environment", "stage", "name", "attributes"])
    )) == 0
    error_message = "label_order may contain only namespace, tenant, environment, stage, name, and attributes."
  }
}

variable "id_length_limit" {
  description = "Maximum length of the generated module ID. Set to 0 for no limit."
  type        = number
  default     = 0

  validation {
    condition     = var.id_length_limit >= 0
    error_message = "id_length_limit must be 0 or greater."
  }
}

variable "labels_as_tags" {
  description = "Context labels to propagate as Vultr tags. Vultr tags are strings, so labels are rendered as key:value."
  type        = list(string)
  default     = ["namespace", "tenant", "environment", "stage", "name", "attributes"]

  validation {
    condition = length(setsubtract(
      toset(var.labels_as_tags),
      toset(["namespace", "tenant", "environment", "stage", "name", "attributes"])
    )) == 0
    error_message = "labels_as_tags may contain only namespace, tenant, environment, stage, name, and attributes."
  }
}

variable "tags" {
  description = "Additional structured tags propagated to Vultr as key:value tag strings."
  type        = map(string)
  default     = {}
}

variable "vultr_tags" {
  description = "Additional provider-native Vultr tag strings applied to nodes."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Vultr region ID."
  type        = string
  default     = "ewr"
}

variable "vpc" {
  description = "Private VPC subnet assigned to the cluster nodes and load balancer."
  type = object({
    ip_block      = string
    prefix_length = number
  })
  default = {
    ip_block      = "10.42.0.0"
    prefix_length = 24
  }

  validation {
    condition     = can(cidrnetmask("${var.vpc.ip_block}/${var.vpc.prefix_length}"))
    error_message = "vpc must define a valid IPv4 CIDR block."
  }

  validation {
    condition     = var.vpc.prefix_length >= 16 && var.vpc.prefix_length <= 28
    error_message = "vpc.prefix_length must be between 16 and 28."
  }
}

variable "node_count" {
  description = "Number of cluster nodes to create."
  type        = number
  default     = 3

  validation {
    condition     = var.node_count >= 1 && floor(var.node_count) == var.node_count
    error_message = "node_count must be a whole number of at least 1."
  }
}

variable "node_plan" {
  description = "Vultr instance plan ID for each node."
  type        = string
  default     = "vc2-2c-4gb"
}

variable "bastion_plan" {
  description = "Vultr instance plan ID for the bastion host."
  type        = string
  default     = "vc2-1c-1gb"
}

variable "os_id" {
  description = "Vultr OS ID for the node image. Defaults to Ubuntu 26.04 LTS x64."
  type        = number
  default     = 2760
}

variable "ssh_public_key" {
  description = "Optional public SSH key to create in Vultr and attach to all nodes."
  type        = string
  default     = null
}

variable "ssh_key_ids" {
  description = "Existing Vultr SSH key IDs to attach to all nodes."
  type        = list(string)
  default     = []
}

variable "user_data" {
  description = "Optional cloud-init user data passed to every node."
  type        = string
  default     = null
  sensitive   = true
}

variable "enable_ipv6" {
  description = "Enable IPv6 on each node."
  type        = bool
  default     = true
}

variable "disable_public_ipv4" {
  description = "Disable public IPv4 on each node. Vultr requires enable_ipv6 to be true when this is enabled."
  type        = bool
  default     = false
}

variable "activation_email" {
  description = "Send Vultr activation emails when nodes are created."
  type        = bool
  default     = false
}

variable "enable_ddos_protection" {
  description = "Enable paid Vultr DDoS protection for each node."
  type        = bool
  default     = false
}

variable "node_firewall_rules" {
  description = "Additional firewall rules applied to the node firewall group. SSH from the VPC CIDR is always included for bastion access."
  type = map(object({
    protocol    = string
    ip_type     = string
    subnet      = string
    subnet_size = number
    port        = string
    notes       = string
  }))
  default = {
    kubernetes_api = {
      protocol    = "tcp"
      ip_type     = "v4"
      subnet      = "0.0.0.0"
      subnet_size = 0
      port        = "6443"
      notes       = "kubernetes api"
    }
    http = {
      protocol    = "tcp"
      ip_type     = "v4"
      subnet      = "0.0.0.0"
      subnet_size = 0
      port        = "80"
      notes       = "http"
    }
    https = {
      protocol    = "tcp"
      ip_type     = "v4"
      subnet      = "0.0.0.0"
      subnet_size = 0
      port        = "443"
      notes       = "https"
    }
  }

  validation {
    condition = alltrue([
      for rule in values(var.node_firewall_rules) : contains(["icmp", "tcp", "udp", "gre", "esp", "ah"], rule.protocol)
    ])
    error_message = "node_firewall_rules protocols must be lowercase Vultr firewall protocols."
  }

  validation {
    condition = alltrue([
      for rule in values(var.node_firewall_rules) : contains(["v4", "v6"], rule.ip_type)
    ])
    error_message = "node_firewall_rules ip_type values must be v4 or v6."
  }

  validation {
    condition = alltrue([
      for rule in values(var.node_firewall_rules) : can(cidrnetmask("${rule.subnet}/${rule.subnet_size}"))
    ])
    error_message = "node_firewall_rules subnet and subnet_size values must form valid CIDR blocks."
  }
}

variable "bastion_firewall_rules" {
  description = "Firewall rules applied to the bastion firewall group."
  type = map(object({
    protocol    = string
    ip_type     = string
    subnet      = string
    subnet_size = number
    port        = string
    notes       = string
  }))
  default = {
    ssh = {
      protocol    = "tcp"
      ip_type     = "v4"
      subnet      = "0.0.0.0"
      subnet_size = 0
      port        = "22"
      notes       = "ssh"
    }
  }

  validation {
    condition = alltrue([
      for rule in values(var.bastion_firewall_rules) : contains(["icmp", "tcp", "udp", "gre", "esp", "ah"], rule.protocol)
    ])
    error_message = "bastion_firewall_rules protocols must be lowercase Vultr firewall protocols."
  }

  validation {
    condition = alltrue([
      for rule in values(var.bastion_firewall_rules) : contains(["v4", "v6"], rule.ip_type)
    ])
    error_message = "bastion_firewall_rules ip_type values must be v4 or v6."
  }

  validation {
    condition = alltrue([
      for rule in values(var.bastion_firewall_rules) : can(cidrnetmask("${rule.subnet}/${rule.subnet_size}"))
    ])
    error_message = "bastion_firewall_rules subnet and subnet_size values must form valid CIDR blocks."
  }
}

variable "load_balancer_algorithm" {
  description = "Vultr load balancer algorithm."
  type        = string
  default     = "roundrobin"

  validation {
    condition     = contains(["roundrobin", "leastconn"], var.load_balancer_algorithm)
    error_message = "load_balancer_algorithm must be roundrobin or leastconn."
  }
}

variable "load_balancer_forwarding_rules" {
  description = "TCP forwarding rules for the Vultr network load balancer."
  type = map(object({
    frontend_protocol = string
    frontend_port     = number
    backend_protocol  = string
    backend_port      = number
  }))
  default = {
    kubernetes_api = {
      frontend_protocol = "tcp"
      frontend_port     = 6443
      backend_protocol  = "tcp"
      backend_port      = 6443
    }
    http = {
      frontend_protocol = "tcp"
      frontend_port     = 80
      backend_protocol  = "tcp"
      backend_port      = 80
    }
    https = {
      frontend_protocol = "tcp"
      frontend_port     = 443
      backend_protocol  = "tcp"
      backend_port      = 443
    }
  }

  validation {
    condition = alltrue([
      for rule in values(var.load_balancer_forwarding_rules) : rule.frontend_protocol == "tcp" && rule.backend_protocol == "tcp"
    ])
    error_message = "Only tcp forwarding rules are allowed for this network load balancer module."
  }

  validation {
    condition = alltrue(flatten([
      for rule in values(var.load_balancer_forwarding_rules) : [
        rule.frontend_port > 0 && rule.frontend_port <= 65535 && floor(rule.frontend_port) == rule.frontend_port,
        rule.backend_port > 0 && rule.backend_port <= 65535 && floor(rule.backend_port) == rule.backend_port,
      ]
    ]))
    error_message = "Load balancer ports must be whole numbers between 1 and 65535."
  }
}

variable "load_balancer_health_check" {
  description = "Health check settings for the Vultr load balancer."
  type = object({
    protocol            = string
    path                = string
    port                = number
    check_interval      = number
    response_timeout    = number
    unhealthy_threshold = number
    healthy_threshold   = number
  })
  default = {
    protocol            = "tcp"
    path                = "/"
    port                = 22
    check_interval      = 15
    response_timeout    = 5
    unhealthy_threshold = 5
    healthy_threshold   = 5
  }

  validation {
    condition     = contains(["http", "tcp"], var.load_balancer_health_check.protocol)
    error_message = "load_balancer_health_check.protocol must be http or tcp."
  }

  validation {
    condition     = var.load_balancer_health_check.port > 0 && var.load_balancer_health_check.port <= 65535 && floor(var.load_balancer_health_check.port) == var.load_balancer_health_check.port
    error_message = "load_balancer_health_check.port must be a whole number between 1 and 65535."
  }
}
