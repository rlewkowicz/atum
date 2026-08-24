locals {
  label_values = {
    namespace   = var.namespace
    tenant      = var.tenant
    environment = var.environment
    stage       = var.stage
    name        = var.name
  }

  ordered_label_parts = flatten([
    for label in var.label_order : label == "attributes" ? var.attributes : [
      lookup(local.label_values, label, null)
    ]
  ])

  full_id = join(var.delimiter, compact([
    for part in local.ordered_label_parts : part == null ? "" : trimspace(part)
  ]))

  id = var.id_length_limit == 0 ? local.full_id : substr(local.full_id, 0, var.id_length_limit)

  labels = merge(local.label_values, {
    attributes = length(var.attributes) == 0 ? null : join(var.delimiter, var.attributes)
  })

  label_tags = compact([
    for label in var.labels_as_tags : try(trimspace(local.labels[label]) == "" ? "" : "${label}:${local.labels[label]}", "")
  ])

  map_tags = compact([
    for key, value in var.tags : trimspace(value) == "" ? "" : "${key}:${value}"
  ])

  tags = distinct(compact(concat(local.label_tags, local.map_tags, var.vultr_tags)))

  names = {
    vpc                    = "${local.id}${var.delimiter}vpc"
    firewall_group         = "${local.id}${var.delimiter}nodes"
    bastion                = "${local.id}${var.delimiter}bastion"
    bastion_firewall_group = "${local.id}${var.delimiter}bastion"
    load_balancer          = "${local.id}${var.delimiter}nlb"
    ssh_key                = "${local.id}${var.delimiter}ssh"
  }

  ssh_public_key = trimspace(var.ssh_public_key == null ? "" : var.ssh_public_key)

  managed_ssh_key_ids = local.ssh_public_key == "" ? [] : [
    vultr_ssh_key.cluster[0].id
  ]

  node_firewall_rules = merge({
    ssh = {
      protocol    = "tcp"
      ip_type     = "v4"
      subnet      = var.vpc.ip_block
      subnet_size = var.vpc.prefix_length
      port        = "22"
      notes       = "ssh from vpc"
    }
  }, var.node_firewall_rules)

  ssh_key_ids = distinct(concat(var.ssh_key_ids, local.managed_ssh_key_ids))
  vpc_id      = try(vultr_vpc.cluster[0].id, null)
}
