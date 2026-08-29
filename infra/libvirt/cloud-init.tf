locals {
  common_packages = [
    "apt-transport-https",
    "ca-certificates",
    "curl",
    "gnupg",
    "python3",
    "qemu-guest-agent",
  ]

  apt_force_ipv4 = <<-EOT
    Acquire::ForceIPv4 "true";
  EOT

  kubernetes_modules = <<-EOT
    overlay
    br_netfilter
    nf_conntrack
    ip_tables
    iptable_nat
    ip6_tables
    xt_conntrack
    cls_bpf
    sch_ingress
    vxlan
  EOT

  kubernetes_performance_sysctl = <<-EOT
    fs.file-max = 2097152
    fs.inotify.max_queued_events = 32768
    fs.inotify.max_user_instances = 8192
    fs.inotify.max_user_watches = 1048576
    fs.nr_open = 2097152
    kernel.keys.root_maxbytes = 25000000
    kernel.keys.root_maxkeys = 1000000
    kernel.pid_max = 4194304
    net.bridge.bridge-nf-call-ip6tables = 1
    net.bridge.bridge-nf-call-iptables = 1
    net.core.bpf_jit_enable = 1
    net.core.default_qdisc = fq
    net.core.netdev_max_backlog = 32768
    net.core.optmem_max = 4194304
    net.core.rmem_default = 262144
    net.core.rmem_max = 134217728
    net.core.somaxconn = 32768
    net.core.wmem_default = 262144
    net.core.wmem_max = 134217728
    net.ipv4.conf.all.forwarding = 1
    net.ipv4.conf.all.rp_filter = 0
    net.ipv4.conf.default.forwarding = 1
    net.ipv4.conf.default.rp_filter = 0
    net.ipv4.ip_forward = 1
    net.ipv4.ip_local_port_range = 1024 65000
    net.ipv4.tcp_fin_timeout = 15
    net.ipv4.tcp_keepalive_intvl = 30
    net.ipv4.tcp_keepalive_probes = 5
    net.ipv4.tcp_keepalive_time = 600
    net.ipv4.tcp_max_syn_backlog = 32768
    net.ipv4.tcp_rmem = 4096 87380 134217728
    net.ipv4.tcp_tw_reuse = 1
    net.ipv4.tcp_wmem = 4096 65536 134217728
    net.netfilter.nf_conntrack_max = 262144
    net.netfilter.nf_conntrack_tcp_timeout_established = 86400
    vm.dirty_background_ratio = 5
    vm.dirty_expire_centisecs = 3000
    vm.dirty_ratio = 20
    vm.dirty_writeback_centisecs = 500
    vm.max_map_count = 262144
    vm.overcommit_memory = 1
    vm.swappiness = 0
    vm.vfs_cache_pressure = 50
  EOT

  kubernetes_security_limits = <<-EOT
    * soft nofile 1048576
    * hard nofile 1048576
    * soft nproc 1048576
    * hard nproc 1048576
    * soft memlock unlimited
    * hard memlock unlimited
    root soft nofile 1048576
    root hard nofile 1048576
    root soft nproc 1048576
    root hard nproc 1048576
    root soft memlock unlimited
    root hard memlock unlimited
  EOT

  node_tuning_script = <<-EOT
    #!/usr/bin/env bash
    set -euo pipefail

    write_if_writable() {
      local path="$1"
      local value="$2"

      if [ -w "$path" ]; then
        printf '%s\n' "$value" > "$path" || true
      fi
    }

    install -d -m 0755 \
      /etc/systemd/system.conf.d \
      /etc/systemd/user.conf.d \
      /etc/systemd/system/containerd.service.d \
      /etc/systemd/system/kubelet.service.d

    printf '%s\n' \
      '[Manager]' \
      'DefaultLimitNOFILE=1048576' \
      'DefaultLimitNPROC=1048576' \
      'DefaultLimitMEMLOCK=infinity' \
      'DefaultTasksMax=infinity' \
      > /etc/systemd/system.conf.d/99-kubernetes-performance.conf

    printf '%s\n' \
      '[Manager]' \
      'DefaultLimitNOFILE=1048576' \
      'DefaultLimitNPROC=1048576' \
      'DefaultLimitMEMLOCK=infinity' \
      'DefaultTasksMax=infinity' \
      > /etc/systemd/user.conf.d/99-kubernetes-performance.conf

    printf '%s\n' \
      '[Service]' \
      'LimitNOFILE=1048576' \
      'LimitNPROC=1048576' \
      'LimitMEMLOCK=infinity' \
      'TasksMax=infinity' \
      > /etc/systemd/system/containerd.service.d/10-limits.conf

    printf '%s\n' \
      '[Service]' \
      'LimitNOFILE=1048576' \
      'LimitNPROC=1048576' \
      'LimitMEMLOCK=infinity' \
      'TasksMax=infinity' \
      > /etc/systemd/system/kubelet.service.d/10-limits.conf

    sysctl -e --system

    for queue in /sys/block/vd*/queue; do
      [ -d "$queue" ] || continue

      if [ -w "$queue/scheduler" ] && grep -qw none "$queue/scheduler"; then
        write_if_writable "$queue/scheduler" none
      fi

      write_if_writable "$queue/read_ahead_kb" 4096
      write_if_writable "$queue/nr_requests" 1024
      write_if_writable "$queue/rotational" 0
    done

    systemctl daemon-reload
  EOT

  bastion_docker_config = jsonencode({
    "data-root"  = "/data/docker"
    "log-driver" = "local"
    "log-opts" = {
      "max-file" = "5"
      "max-size" = "20m"
    }
  })

  node_user_data = join("\n", [
    "#cloud-config",
    yamlencode({
      apt = {
        conf = local.apt_force_ipv4
      }
      disable_root   = false
      package_update = true
      packages       = concat(local.common_packages, ["containerd"])
      ssh_pwauth     = false
      users = [{
        lock_passwd         = true
        name                = "root"
        shell               = "/bin/bash"
        ssh_authorized_keys = [local.ssh_public_key]
      }]
      write_files = [
        {
          content     = local.apt_force_ipv4
          path        = "/etc/apt/apt.conf.d/99-force-ipv4"
          permissions = "0644"
        },
        {
          content     = local.kubernetes_modules
          path        = "/etc/modules-load.d/k8s.conf"
          permissions = "0644"
        },
        {
          content     = local.kubernetes_performance_sysctl
          path        = "/etc/sysctl.d/99-kubernetes-performance.conf"
          permissions = "0644"
        },
        {
          content     = local.kubernetes_security_limits
          path        = "/etc/security/limits.d/99-kubernetes-performance.conf"
          permissions = "0644"
        },
        {
          content     = local.node_tuning_script
          path        = "/usr/local/sbin/atum-node-tune.sh"
          permissions = "0755"
        },
      ]
      runcmd = [
        "while read -r module; do [ -z \"$module\" ] && continue; modprobe \"$module\" || true; done < /etc/modules-load.d/k8s.conf",
        "/usr/local/sbin/atum-node-tune.sh",
        "systemctl enable --now qemu-guest-agent",
        "systemctl enable --now containerd",
      ]
    }),
  ])

  bastion_user_data = join("\n", [
    "#cloud-config",
    yamlencode({
      apt = {
        conf = local.apt_force_ipv4
      }
      disable_root   = false
      package_update = true
      packages       = concat(local.common_packages, ["docker.io", "docker-compose-v2"])
      ssh_pwauth     = false
      users = [{
        lock_passwd         = true
        name                = "root"
        shell               = "/bin/bash"
        ssh_authorized_keys = [local.ssh_public_key]
      }]
      disk_setup = {
        "/dev/vdb" = {
          layout     = true
          overwrite  = false
          table_type = "gpt"
        }
      }
      fs_setup = [{
        device     = "/dev/vdb"
        filesystem = "ext4"
        label      = "atum-data"
        partition  = "auto"
      }]
      mounts = [["LABEL=atum-data", "/data", "ext4", "defaults,nofail", "0", "2"]]
      write_files = [
        {
          content     = local.apt_force_ipv4
          path        = "/etc/apt/apt.conf.d/99-force-ipv4"
          permissions = "0644"
        },
        {
          content     = local.bastion_docker_config
          path        = "/etc/docker/daemon.json"
          permissions = "0644"
        },
      ]
      runcmd = [
        "install -d -m 0755 /data/docker /data/harbor /data/forgejo /data/kubespray-files /opt/atum-seed",
        "chown -R 1000:1000 /data/forgejo",
        "systemctl enable --now qemu-guest-agent",
        "systemctl enable docker",
        "systemctl restart docker",
      ]
    }),
  ])

  haproxy_backends = join("\n", [
    for index, ip in local.node_ips : format("    server %s %s:6443 check", local.node_names[index], ip)
  ])

  haproxy_config = <<-EOT
    global
        log /dev/log local0
        log /dev/log local1 notice
        daemon

    defaults
        log global
        mode tcp
        option tcplog
        timeout connect 10s
        timeout client 1m
        timeout server 1m

    frontend kubernetes_api
        bind ${var.load_balancer_ip}:6443
        default_backend kubernetes_api

    backend kubernetes_api
        balance roundrobin
${local.haproxy_backends}
  EOT

  load_balancer_user_data = join("\n", [
    "#cloud-config",
    yamlencode({
      apt = {
        conf = local.apt_force_ipv4
      }
      disable_root   = false
      package_update = true
      packages       = concat(local.common_packages, ["haproxy"])
      ssh_pwauth     = false
      users = [{
        lock_passwd         = true
        name                = "root"
        shell               = "/bin/bash"
        ssh_authorized_keys = [local.ssh_public_key]
      }]
      write_files = [
        {
          content     = local.apt_force_ipv4
          path        = "/etc/apt/apt.conf.d/99-force-ipv4"
          permissions = "0644"
        },
        {
          content     = local.haproxy_config
          path        = "/etc/haproxy/haproxy.cfg"
          permissions = "0644"
        },
      ]
      runcmd = [
        "systemctl enable --now qemu-guest-agent",
        "systemctl enable --now haproxy",
      ]
    }),
  ])

  load_balancer_network_config = yamlencode({
    ethernets = {
      primary = {
        dhcp4 = true
        match = {
          macaddress = local.load_balancer_mac
        }
        "set-name" = "eth0"
      }
    }
    version = 2
  })

  bastion_network_config = yamlencode({
    ethernets = {
      primary = {
        addresses = ["${var.bastion_ip}/${tonumber(split("/", var.network_cidr)[1])}"]
        dhcp4     = false
        match = {
          macaddress = local.bastion_mac
        }
        nameservers = {
          addresses = [cidrhost(var.network_cidr, 1)]
        }
        routes = [{
          to  = "default"
          via = cidrhost(var.network_cidr, 1)
        }]
        "set-name" = "eth0"
      }
    }
    version = 2
  })

  node_network_configs = [
    for index, mac in local.node_macs : yamlencode({
      ethernets = {
        primary = {
          dhcp4 = true
          match = {
            macaddress = mac
          }
          "set-name" = "eth0"
        }
      }
      version = 2
    })
  ]
}

resource "libvirt_cloudinit_disk" "load_balancer" {
  name           = "${local.load_balancer_name}-cloudinit.iso"
  user_data      = local.load_balancer_user_data
  meta_data      = yamlencode({ instance-id = local.load_balancer_name, local-hostname = local.load_balancer_name })
  network_config = local.load_balancer_network_config
}

resource "libvirt_cloudinit_disk" "bastion" {
  name           = "${local.bastion_name}-cloudinit.iso"
  user_data      = local.bastion_user_data
  meta_data      = yamlencode({ instance-id = local.bastion_name, local-hostname = local.bastion_name })
  network_config = local.bastion_network_config
}

resource "libvirt_cloudinit_disk" "node" {
  count          = var.node_count
  name           = "${local.node_names[count.index]}-cloudinit.iso"
  user_data      = local.node_user_data
  meta_data      = yamlencode({ instance-id = local.node_names[count.index], local-hostname = local.node_names[count.index] })
  network_config = local.node_network_configs[count.index]
}
