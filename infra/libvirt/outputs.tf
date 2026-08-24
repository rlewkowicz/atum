output "node_labels" {
  description = "Local libvirt node labels."
  value       = local.node_names
}

output "node_main_ips" {
  description = "Local reachable IPv4 addresses for the nodes."
  value       = local.node_ips
}

output "node_internal_ips" {
  description = "Cluster-internal IPv4 addresses for the nodes."
  value       = local.node_ips
}

output "load_balancer_ipv4" {
  description = "Local reachable IPv4 address for the HAProxy load balancer."
  value       = var.load_balancer_ip
}

output "dns_server" {
  description = "IPv4 address of the Terraform-owned libvirt dnsmasq service."
  value       = var.dns_server
}

output "platform_domain" {
  description = "Local application domain served by the Terraform-owned libvirt dnsmasq service."
  value       = var.platform_domain
}

output "public_ingress_vip" {
  description = "Static local address assigned to the public Istio gateway."
  value       = var.public_ingress_vip
}

output "passthrough_ingress_vip" {
  description = "Static local address assigned to the TLS-passthrough Istio gateway."
  value       = var.passthrough_ingress_vip
}

output "load_balancer_range" {
  description = "Inclusive address range reserved for dynamic local LoadBalancer Services."
  value       = "${var.load_balancer_range.start}-${var.load_balancer_range.end}"
}

output "bastion_main_ip" {
  description = "Local reachable IPv4 address for the bastion host."
  value       = var.bastion_ip
}

output "bastion_label" {
  description = "Local bastion label."
  value       = local.bastion_name
}

output "bastion_internal_ip" {
  description = "Cluster-internal IPv4 address for the bastion host."
  value       = var.bastion_ip
}

output "seed_forgejo_url" {
  description = "Private HTTP origin for the Terraform-owned Forgejo seed service."
  value       = var.seed_forgejo_url
}

output "seed_harbor_url" {
  description = "Private HTTP origin for the Terraform-owned Harbor seed registry."
  value       = var.seed_harbor_url
}

output "seed_plane_configured" {
  description = "Whether Terraform verified and reconciled the lock-bound seed payload."
  value       = length(terraform_data.seed_plane) == 1
}
