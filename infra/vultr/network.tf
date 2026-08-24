resource "vultr_vpc" "cluster" {
  count = var.enabled ? 1 : 0

  description    = local.names.vpc
  region         = var.region
  v4_subnet      = var.vpc.ip_block
  v4_subnet_mask = var.vpc.prefix_length
}
