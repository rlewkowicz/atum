# Vultr Cluster Primitives

Terraform root module for the Vultr infrastructure layer. It creates the provider primitives needed before cluster bootstrap:

- 1 VPC
- 1 node firewall group
- 1 bastion firewall group
- 1 bastion host
- 3 compute nodes by default
- 1 TCP load balancer attached to the VPC
- Optional managed Vultr SSH key

## Naming

Resource names are generated from a label context:

```text
namespace-environment-stage-name-attributes
```

The default ID is `atum-prod-atum`. Labels are propagated to Vultr node tags as `key:value` strings because Vultr tags are provider-native strings, not key/value maps.

## Prerequisites

- Terraform 1.6 or newer
- Vultr API key exported as `VULTR_API_KEY`
- A Vultr OS ID, plan ID, and region that are available in the account

## Usage

```hcl
module "vultr_cluster" {
  source = "./infra/vultr"

  namespace = "atum"
  stage     = "prod"
  name      = "atum"

  region    = "ewr"
  node_plan = "vc2-2c-4gb"
  bastion_plan = "vc2-1c-1gb"
  os_id     = 2760

  ssh_key_ids = ["00000000-0000-0000-0000-000000000000"]

  tags = {
    managed-by = "terraform"
    service    = "cluster"
  }
}
```

## Defaults

The default load balancer rules are TCP only:

- `6443 -> 6443`
- `80 -> 80`
- `443 -> 443`

The default health check is TCP on port `22` so the load balancer can mark freshly provisioned nodes healthy before a cluster runtime is installed. Override `load_balancer_health_check` when the node bootstrap process owns a better readiness port.

The module creates a bastion by default. Node SSH is allowed from the VPC CIDR, while public SSH ingress is owned by `bastion_firewall_rules`. The Terraform outputs include `bastion_main_ip` and `bastion_internal_ip`; `atum orch inventory` uses those outputs to route node SSH through the bastion while targeting node internal IPs.

## Commands

```bash
export VULTR_API_KEY="..."
terraform -chdir=infra/vultr init
terraform -chdir=infra/vultr plan
terraform -chdir=infra/vultr apply
```
