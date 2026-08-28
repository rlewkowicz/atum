resource "libvirt_volume" "base" {
  name = "${var.name_prefix}-ubuntu-base.qcow2"
  pool = var.storage_pool

  create = {
    content = {
      url = var.base_cloud_image_url
    }
  }

  target = {
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_volume" "load_balancer" {
  name          = "${local.load_balancer_name}.qcow2"
  pool          = var.storage_pool
  capacity      = local.disk_size_bytes
  capacity_unit = "bytes"

  backing_store = {
    path = libvirt_volume.base.path
    format = {
      type = "qcow2"
    }
  }

  target = {
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_volume" "bastion" {
  name          = "${local.bastion_name}.qcow2"
  pool          = var.storage_pool
  capacity      = local.disk_size_bytes
  capacity_unit = "bytes"

  backing_store = {
    path = libvirt_volume.base.path
    format = {
      type = "qcow2"
    }
  }

  target = {
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_volume" "bastion_data" {
  name          = "${local.bastion_name}-data.qcow2"
  pool          = var.storage_pool
  capacity      = local.bastion_data_size_bytes
  capacity_unit = "bytes"

  target = {
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_volume" "node" {
  count         = var.node_count
  name          = "${local.node_names[count.index]}.qcow2"
  pool          = var.storage_pool
  capacity      = local.disk_size_bytes
  capacity_unit = "bytes"

  backing_store = {
    path = libvirt_volume.base.path
    format = {
      type = "qcow2"
    }
  }

  target = {
    format = {
      type = "qcow2"
    }
  }
}

resource "libvirt_domain" "load_balancer" {
  name        = local.load_balancer_name
  type        = "kvm"
  memory      = var.load_balancer_memory_mib
  memory_unit = "MiB"
  vcpu        = var.load_balancer_cpus
  autostart   = true
  running     = true

  os = {
    type         = "hvm"
    type_arch    = "x86_64"
    type_machine = "q35"
    boot_devices = [{
      dev = "hd"
    }]
  }

  features = {
    acpi = true
  }

  cpu = {
    mode = "host-passthrough"
  }

  devices = {
    disks = [
      {
        source = {
          volume = {
            pool   = var.storage_pool
            volume = libvirt_volume.load_balancer.name
          }
        }
        target = {
          dev = "vda"
          bus = "virtio"
        }
        driver = {
          type = "qcow2"
        }
      },
      {
        device = "cdrom"
        source = {
          file = {
            file = libvirt_cloudinit_disk.load_balancer.path
          }
        }
        target = {
          dev = "sda"
          bus = "sata"
        }
      },
    ]
    interfaces = [{
      mac = {
        address = local.load_balancer_mac
      }
      model = {
        type = "virtio"
      }
      source = {
        network = {
          network = libvirt_network.atum.name
        }
      }
      wait_for_ip = {
        source  = "lease"
        timeout = 300
      }
    }]
    graphics = [{
      spice = {
        auto_port = true
        listen    = "127.0.0.1"
      }
    }]
    channels = [{
      target = {
        virt_io = {
          name = "org.qemu.guest_agent.0"
        }
      }
    }]
  }
}

resource "libvirt_domain" "bastion" {
  name        = local.bastion_name
  type        = "kvm"
  memory      = var.bastion_memory_mib
  memory_unit = "MiB"
  vcpu        = var.bastion_cpus
  autostart   = true
  running     = true

  os = {
    type         = "hvm"
    type_arch    = "x86_64"
    type_machine = "q35"
    boot_devices = [{
      dev = "hd"
    }]
  }

  features = {
    acpi = true
  }

  cpu = {
    mode = "host-passthrough"
  }

  devices = {
    disks = [
      {
        source = {
          volume = {
            pool   = var.storage_pool
            volume = libvirt_volume.bastion.name
          }
        }
        target = {
          dev = "vda"
          bus = "virtio"
        }
        driver = {
          type = "qcow2"
        }
      },
      {
        source = {
          volume = {
            pool   = var.storage_pool
            volume = libvirt_volume.bastion_data.name
          }
        }
        target = {
          dev = "vdb"
          bus = "virtio"
        }
        driver = {
          type = "qcow2"
        }
      },
      {
        device = "cdrom"
        source = {
          file = {
            file = libvirt_cloudinit_disk.bastion.path
          }
        }
        target = {
          dev = "sda"
          bus = "sata"
        }
      },
    ]
    interfaces = [{
      mac = {
        address = local.bastion_mac
      }
      model = {
        type = "virtio"
      }
      source = {
        network = {
          network = libvirt_network.atum.name
        }
      }
    }]
    graphics = [{
      spice = {
        auto_port = true
        listen    = "127.0.0.1"
      }
    }]
    channels = [{
      target = {
        virt_io = {
          name = "org.qemu.guest_agent.0"
        }
      }
    }]
  }
}

resource "libvirt_domain" "node" {
  count       = var.node_count
  name        = local.node_names[count.index]
  type        = "kvm"
  memory      = var.node_memory_mib
  memory_unit = "MiB"
  vcpu        = var.node_cpus
  autostart   = true
  running     = true

  os = {
    type         = "hvm"
    type_arch    = "x86_64"
    type_machine = "q35"
    boot_devices = [{
      dev = "hd"
    }]
  }

  features = {
    acpi = true
  }

  cpu = {
    mode = "host-passthrough"
  }

  devices = {
    disks = [
      {
        source = {
          volume = {
            pool   = var.storage_pool
            volume = libvirt_volume.node[count.index].name
          }
        }
        target = {
          dev = "vda"
          bus = "virtio"
        }
        driver = {
          type  = "qcow2"
          cache = "none"
          io    = "native"
        }
      },
      {
        device = "cdrom"
        source = {
          file = {
            file = libvirt_cloudinit_disk.node[count.index].path
          }
        }
        target = {
          dev = "sda"
          bus = "sata"
        }
      },
    ]
    interfaces = [{
      mac = {
        address = local.node_macs[count.index]
      }
      model = {
        type = "virtio"
      }
      source = {
        network = {
          network = libvirt_network.atum.name
        }
      }
      wait_for_ip = {
        source  = "lease"
        timeout = 300
      }
    }]
    graphics = [{
      spice = {
        auto_port = true
        listen    = "127.0.0.1"
      }
    }]
    channels = [{
      target = {
        virt_io = {
          name = "org.qemu.guest_agent.0"
        }
      }
    }]
  }
}

resource "terraform_data" "domain_stop_guard" {
  for_each = local.cluster_domain_names

  input = {
    name = each.value
    uri  = var.libvirt_uri
  }

  provisioner "local-exec" {
    when    = destroy
    command = "/usr/bin/env bash \"$ATUM_DOMAIN_STOP_SCRIPT\""

    environment = {
      ATUM_DOMAIN_STOP_SCRIPT = "${path.module}/scripts/stop-domain.sh"
      ATUM_LIBVIRT_DOMAIN     = self.input.name
      ATUM_LIBVIRT_URI        = self.input.uri
    }
  }

  depends_on = [
    libvirt_domain.load_balancer,
    libvirt_domain.node,
  ]
}

resource "terraform_data" "bastion_stop_guard" {
  input = {
    name = local.bastion_name
    uri  = var.libvirt_uri
  }

  provisioner "local-exec" {
    when    = destroy
    command = "/usr/bin/env bash \"$ATUM_DOMAIN_STOP_SCRIPT\""

    environment = {
      ATUM_DOMAIN_STOP_SCRIPT = "${path.module}/scripts/stop-domain.sh"
      ATUM_LIBVIRT_DOMAIN     = self.input.name
      ATUM_LIBVIRT_URI        = self.input.uri
    }
  }

  depends_on = [
    libvirt_domain.bastion,
  ]
}
