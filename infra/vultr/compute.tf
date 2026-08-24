resource "vultr_instance" "nodes" {
  count = var.enabled ? var.node_count : 0

  region              = var.region
  plan                = var.node_plan
  os_id               = var.os_id
  label               = format("%s%snode%s%02d", local.id, var.delimiter, var.delimiter, count.index + 1)
  hostname            = format("%s%snode%s%02d", local.id, var.delimiter, var.delimiter, count.index + 1)
  tags                = local.tags
  firewall_group_id   = vultr_firewall_group.nodes[0].id
  ssh_key_ids         = local.ssh_key_ids
  vpc_ids             = [local.vpc_id]
  user_data           = var.user_data
  enable_ipv6         = var.enable_ipv6
  disable_public_ipv4 = var.disable_public_ipv4
  activation_email    = var.activation_email
  ddos_protection     = var.enable_ddos_protection
}

resource "vultr_instance" "bastion" {
  count = var.enabled ? 1 : 0

  region              = var.region
  plan                = var.bastion_plan
  os_id               = var.os_id
  label               = local.names.bastion
  hostname            = local.names.bastion
  tags                = local.tags
  firewall_group_id   = vultr_firewall_group.bastion[0].id
  ssh_key_ids         = local.ssh_key_ids
  vpc_ids             = [local.vpc_id]
  user_data           = var.user_data
  enable_ipv6         = var.enable_ipv6
  disable_public_ipv4 = false
  activation_email    = var.activation_email
  ddos_protection     = var.enable_ddos_protection
}
