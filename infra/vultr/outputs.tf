output "enabled" {
  description = "Whether module resources are enabled."
  value       = var.enabled
}

output "id" {
  description = "Generated module ID used as the resource name prefix."
  value       = local.id
}

output "labels" {
  description = "Resolved naming labels."
  value       = local.labels
}

output "tags" {
  description = "Resolved provider-native Vultr tags applied to nodes."
  value       = local.tags
}

output "names" {
  description = "Resolved names for singleton resources."
  value       = local.names
}

output "vpc_id" {
  description = "Vultr VPC ID."
  value       = local.vpc_id
}

output "vpc_cidr" {
  description = "VPC CIDR block."
  value       = "${var.vpc.ip_block}/${var.vpc.prefix_length}"
}

output "firewall_group_id" {
  description = "Node firewall group ID."
  value       = try(vultr_firewall_group.nodes[0].id, null)
}

output "bastion_firewall_group_id" {
  description = "Bastion firewall group ID."
  value       = try(vultr_firewall_group.bastion[0].id, null)
}

output "ssh_key_ids" {
  description = "SSH key IDs attached to all instances."
  value       = local.ssh_key_ids
}

output "node_ids" {
  description = "Vultr node instance IDs."
  value       = vultr_instance.nodes[*].id
}

output "node_labels" {
  description = "Vultr node labels."
  value       = vultr_instance.nodes[*].label
}

output "node_main_ips" {
  description = "Public IPv4 addresses for the nodes."
  value       = vultr_instance.nodes[*].main_ip
}

output "node_internal_ips" {
  description = "VPC IPv4 addresses for the nodes."
  value       = vultr_instance.nodes[*].internal_ip
}

output "bastion_id" {
  description = "Vultr bastion instance ID."
  value       = try(vultr_instance.bastion[0].id, null)
}

output "bastion_label" {
  description = "Vultr bastion label."
  value       = try(vultr_instance.bastion[0].label, null)
}

output "bastion_main_ip" {
  description = "Public IPv4 address for the bastion host."
  value       = try(vultr_instance.bastion[0].main_ip, null)
}

output "bastion_internal_ip" {
  description = "VPC IPv4 address for the bastion host."
  value       = try(vultr_instance.bastion[0].internal_ip, null)
}

output "load_balancer_id" {
  description = "Vultr load balancer ID."
  value       = try(vultr_load_balancer.network[0].id, null)
}

output "load_balancer_ipv4" {
  description = "Public IPv4 address for the Vultr load balancer."
  value       = try(vultr_load_balancer.network[0].ipv4, null)
}

output "load_balancer_ipv6" {
  description = "Public IPv6 address for the Vultr load balancer."
  value       = try(vultr_load_balancer.network[0].ipv6, null)
}
