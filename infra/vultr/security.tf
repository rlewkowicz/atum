resource "vultr_ssh_key" "cluster" {
  count = var.enabled && local.ssh_public_key != "" ? 1 : 0

  name    = local.names.ssh_key
  ssh_key = local.ssh_public_key
}

resource "vultr_firewall_group" "nodes" {
  count = var.enabled ? 1 : 0

  description = local.names.firewall_group
}

resource "vultr_firewall_group" "bastion" {
  count = var.enabled ? 1 : 0

  description = local.names.bastion_firewall_group
}

resource "vultr_firewall_rule" "nodes" {
  for_each = var.enabled ? local.node_firewall_rules : {}

  firewall_group_id = vultr_firewall_group.nodes[0].id
  protocol          = each.value.protocol
  ip_type           = each.value.ip_type
  subnet            = each.value.subnet
  subnet_size       = each.value.subnet_size
  port              = each.value.port
  notes             = each.value.notes
}

resource "vultr_firewall_rule" "bastion" {
  for_each = var.enabled ? var.bastion_firewall_rules : {}

  firewall_group_id = vultr_firewall_group.bastion[0].id
  protocol          = each.value.protocol
  ip_type           = each.value.ip_type
  subnet            = each.value.subnet
  subnet_size       = each.value.subnet_size
  port              = each.value.port
  notes             = each.value.notes
}
