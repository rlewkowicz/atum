locals {
  disk_size_bytes         = var.disk_size_gib * 1024 * 1024 * 1024
  bastion_data_size_bytes = var.bastion_data_disk_size_gib * 1024 * 1024 * 1024
  load_balancer_name      = "${var.name_prefix}-lb"
  load_balancer_mac       = "52:54:00:61:74:0a"
  bastion_name            = "${var.name_prefix}-bastion"
  bastion_mac             = "52:54:00:61:74:09"
  node_names              = [for index in range(var.node_count) : format("%s-node-%d", var.name_prefix, index + 1)]
  node_ips                = [for index in range(var.node_count) : var.node_ips[index]]
  node_macs               = [for index in range(var.node_count) : format("52:54:00:61:74:%02x", index + 11)]
  cluster_domain_names    = toset(concat([local.load_balancer_name], local.node_names))
  ssh_public_key          = trimspace(file("${pathexpand(var.ssh_private_key_path)}.pub"))
  dhcp_range              = { start = "10.77.0.100", end = "10.77.0.199" }
  infrastructure_ips      = concat([var.dns_server, var.bastion_ip, var.load_balancer_ip], local.node_ips)
  static_ips              = concat(local.infrastructure_ips, [var.public_ingress_vip, var.passthrough_ingress_vip])
  reserved_ips            = concat(local.static_ips, [local.dhcp_range.start, local.dhcp_range.end, var.load_balancer_range.start, var.load_balancer_range.end])
  static_ip_keys = [
    for address in local.static_ips :
    try(sum([for index, octet in split(".", address) : tonumber(octet) * pow(256, 3 - index)]), -1)
  ]
  load_balancer_range_key = [
    for address in [var.load_balancer_range.start, var.load_balancer_range.end] :
    try(sum([for index, octet in split(".", address) : tonumber(octet) * pow(256, 3 - index)]), -1)
  ]
  dhcp_range_key = [
    for address in [local.dhcp_range.start, local.dhcp_range.end] :
    try(sum([for index, octet in split(".", address) : tonumber(octet) * pow(256, 3 - index)]), -1)
  ]

  dhcp_hosts = concat(
    [
      {
        hostname = local.bastion_name
        ip       = var.bastion_ip
        mac      = local.bastion_mac
      },
      {
        hostname = local.load_balancer_name
        ip       = var.load_balancer_ip
        mac      = local.load_balancer_mac
      },
    ],
    [
      for index, name in local.node_names : {
        hostname = name
        ip       = local.node_ips[index]
        mac      = local.node_macs[index]
      }
    ],
  )
}

resource "libvirt_network" "atum" {
  name      = var.network_name
  autostart = true

  forward = {
    mode = "nat"
  }

  domain = {
    name = var.domain_name
  }

  ips = [{
    address = var.dns_server
    prefix  = tonumber(split("/", var.network_cidr)[1])
    dhcp = {
      ranges = [local.dhcp_range]
      hosts = [
        for host in local.dhcp_hosts : {
          ip   = host.ip
          mac  = host.mac
          name = host.hostname
        }
      ]
    }
  }]

  dnsmasq_options = {
    option = concat(
      [{ value = "address=/${var.platform_domain}/${var.public_ingress_vip}" }],
      [
        for label in sort(var.passthrough_hosts) :
        { value = "address=/${label}.${var.platform_domain}/${var.passthrough_ingress_vip}" }
      ],
    )
  }

  dns = {
    enable = "yes"
  }

  lifecycle {
    precondition {
      condition     = length(var.node_ips) >= var.node_count
      error_message = "node_ips must contain at least node_count addresses."
    }
    precondition {
      condition = alltrue([
        for address in local.reserved_ips :
        try(
          cidrhost("${address}/${split("/", var.network_cidr)[1]}", 0) == cidrhost(var.network_cidr, 0),
          false,
        )
      ])
      error_message = "Every static address and allocator range endpoint must belong to network_cidr."
    }
    precondition {
      condition = alltrue([
        for address in local.reserved_ips :
        try(address != cidrhost(var.network_cidr, 0) && address != cidrhost(var.network_cidr, -1), false)
      ])
      error_message = "Static addresses and allocator range endpoints may not use the network or broadcast address."
    }
    precondition {
      condition     = try(var.dns_server == cidrhost(var.network_cidr, 1), false)
      error_message = "dns_server must be the first usable address in network_cidr."
    }
    precondition {
      condition     = length(distinct(local.static_ips)) == length(local.static_ips)
      error_message = "The gateway, bastion, HAProxy, node, and ingress addresses must be unique."
    }
    precondition {
      condition = alltrue([
        for address in local.static_ip_keys :
        address < local.load_balancer_range_key[0] || address > local.load_balancer_range_key[1]
      ])
      error_message = "load_balancer_range may not overlap the gateway, bastion, HAProxy, nodes, or static ingress VIPs."
    }
    precondition {
      condition     = local.load_balancer_range_key[1] < local.dhcp_range_key[0] || local.dhcp_range_key[1] < local.load_balancer_range_key[0]
      error_message = "load_balancer_range may not overlap the libvirt dynamic DHCP range."
    }
    precondition {
      condition = alltrue([
        for address in local.static_ip_keys :
        address < local.dhcp_range_key[0] || address > local.dhcp_range_key[1]
      ])
      error_message = "The libvirt dynamic DHCP range may not overlap the gateway, bastion, HAProxy, nodes, or static ingress VIPs."
    }
  }
}
