locals {
  seed_enabled = var.seed_archive_path != ""
  seed_harbor_config_version = local.seed_enabled ? format("%s.0", join(".", slice(
    split(".", trimprefix(var.seed_harbor_version, "v")),
    0,
    2,
  ))) : "0.0.0"
  seed_harbor_database_password = substr(sha256(var.seed_harbor_secret_key), 0, 32)
  seed_harbor_configuration = templatefile("${path.module}/templates/harbor.yml.tftpl", {
    harbor_admin_password = jsonencode(var.seed_harbor_admin_password)
    harbor_config_version = local.seed_harbor_config_version
    harbor_host           = var.bastion_ip
    harbor_url            = jsonencode(var.seed_harbor_url)
    database_password     = jsonencode(local.seed_harbor_database_password)
  })
  seed_forgejo_compose = templatefile("${path.module}/templates/forgejo-compose.yaml.tftpl", {
    forgejo_admin_password = jsonencode(var.seed_forgejo_admin_password)
    forgejo_admin_username = jsonencode(var.seed_forgejo_username)
    forgejo_host           = var.bastion_ip
    forgejo_image          = jsonencode(var.seed_forgejo_image)
    forgejo_url            = jsonencode(var.seed_forgejo_url)
  })
  seed_reconcile_script = file("${path.module}/scripts/reconcile-seed-plane.sh")
}

resource "terraform_data" "seed_plane" {
  count = local.seed_enabled ? 1 : 0

  triggers_replace = {
    archive_sha256 = var.seed_archive_sha256
    bastion_id     = libvirt_domain.bastion.id
    forgejo_config = sha256(local.seed_forgejo_compose)
    harbor_config  = sha256(local.seed_harbor_configuration)
    reconcile      = sha256(local.seed_reconcile_script)
  }

  lifecycle {
    precondition {
      condition     = can(regex("^[0-9a-f]{64}$", var.seed_archive_sha256))
      error_message = "seed_archive_sha256 must be the exact lowercase SHA-256 of seed_archive_path."
    }
    precondition {
      condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+$", var.seed_harbor_version))
      error_message = "seed_harbor_version must be an exact v-prefixed release."
    }
    precondition {
      condition = (
        startswith(var.seed_archive_path, "/") &&
        var.seed_forgejo_image != "" &&
        var.seed_forgejo_username != "" &&
        length(var.seed_forgejo_admin_password) >= 24 &&
        length(var.seed_harbor_admin_password) >= 24 &&
        length(var.seed_harbor_secret_key) == 16
      )
      error_message = "seed reconciliation requires an absolute archive path, exact seed images, typed Forgejo and Harbor credentials, and a 16-character Harbor secret."
    }
    precondition {
      condition = (
        var.seed_forgejo_url == "http://${var.bastion_ip}:3000" &&
        var.seed_harbor_url == "http://${var.bastion_ip}:32443"
      )
      error_message = "seed service URLs must match the private libvirt bastion addresses."
    }
  }

  connection {
    type        = "ssh"
    host        = var.bastion_ip
    user        = "root"
    private_key = file(pathexpand(var.ssh_private_key_path))
    timeout     = "10m"
  }

  provisioner "remote-exec" {
    inline = [
      "cloud-init status --wait --long",
      "install -d -m 0700 /data/atum-seed/incoming",
    ]
  }

  provisioner "file" {
    source      = pathexpand(var.seed_archive_path)
    destination = "/data/atum-seed/incoming/atum-seed.tar"
  }

  provisioner "file" {
    content     = local.seed_harbor_configuration
    destination = "/data/atum-seed/incoming/harbor.yml"
  }

  provisioner "file" {
    content     = local.seed_forgejo_compose
    destination = "/data/atum-seed/incoming/forgejo-compose.yaml"
  }

  provisioner "file" {
    content     = local.seed_reconcile_script
    destination = "/data/atum-seed/incoming/reconcile-seed-plane.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod 0600 /data/atum-seed/incoming/harbor.yml /data/atum-seed/incoming/forgejo-compose.yaml",
      "chmod 0700 /data/atum-seed/incoming/reconcile-seed-plane.sh",
      "/data/atum-seed/incoming/reconcile-seed-plane.sh '${var.seed_archive_sha256}' '${var.seed_harbor_version}'",
    ]
  }

  depends_on = [libvirt_domain.bastion]
}
