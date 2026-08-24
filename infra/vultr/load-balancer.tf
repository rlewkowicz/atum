resource "vultr_load_balancer" "network" {
  count = var.enabled ? 1 : 0

  region              = var.region
  label               = local.names.load_balancer
  balancing_algorithm = var.load_balancer_algorithm
  attached_instances  = vultr_instance.nodes[*].id
  vpc                 = local.vpc_id

  dynamic "forwarding_rules" {
    for_each = var.load_balancer_forwarding_rules

    content {
      frontend_protocol = forwarding_rules.value.frontend_protocol
      frontend_port     = forwarding_rules.value.frontend_port
      backend_protocol  = forwarding_rules.value.backend_protocol
      backend_port      = forwarding_rules.value.backend_port
    }
  }

  health_check {
    protocol            = var.load_balancer_health_check.protocol
    path                = var.load_balancer_health_check.path
    port                = var.load_balancer_health_check.port
    check_interval      = var.load_balancer_health_check.check_interval
    response_timeout    = var.load_balancer_health_check.response_timeout
    unhealthy_threshold = var.load_balancer_health_check.unhealthy_threshold
    healthy_threshold   = var.load_balancer_health_check.healthy_threshold
  }
}
