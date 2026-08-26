# Local Libvirt Harness

This provider layer creates one bastion VM, one HAProxy load balancer VM, and Kubernetes node VMs on a local NAT libvirt network. It emits the same Terraform output keys consumed by `atum orch inventory`.

Expected host prerequisites:

- Terraform.
- Libvirt with QEMU/KVM and a writable system storage pool.
- The `dmacvicar/libvirt` Terraform provider.
- An SSH public key at `~/.ssh/id_ed25519.pub`, or `ssh_public_key_path` set to another public key.
- Python 3.11 or newer for `atum orchestration prepare`, which hydrates and prepares every exact Kubespray release in the committed ladder.
- A host CPU with virtualization support exposed through `host-passthrough`; Kubernetes node guest kernels must support Cilium's eBPF datapath.

Managed commands probe these prerequisites before mutation and aggregate all
missing or incompatible tools with official installation links. The local
profile also verifies the configured system-libvirt connection and `/dev/kvm`;
a failed preflight stops before Terraform, host DNS, or CA trust changes.

`atum infra libvirt permissions` manages the intentionally broad all-users Polkit rule when a dedicated development host permits that trust model. `atum infra libvirt forwarding` manages persistent, bridge-scoped firewalld exceptions after Terraform creates the network. Each namespace requires an explicit `install`, `status`, or `uninstall`; mutations require root. Terraform itself never elevates privileges or mutates the host firewall.

Run from the repository root:

```sh
atum infra terraform init
atum infra apply
atum orchestration prepare
atum orch inventory
atum orch apply --become
KUBECONFIG=orchestration/inventory/atum/artifacts/admin.conf kubectl get nodes -o wide
```

The harness defaults to the direct QEMU daemon socket because some modular libvirt hosts route `qemu:///system` through a failing proxy socket. Override `libvirt_uri` when your host needs a different libvirt connection:

```sh
atum infra apply -var='libvirt_uri=qemu:///system'
```

The local target owns this explicit `10.77.0.0/24` allocation:

| Purpose | Address or range | Runtime owner |
| --- | --- | --- |
| libvirt gateway and DNS server | `10.77.0.1` | Terraform/libvirt |
| bastion | `10.77.0.9` | Terraform/libvirt |
| Kubernetes API HAProxy | `10.77.0.10` | Terraform/libvirt |
| Kubernetes nodes | `10.77.0.11-10.77.0.13` | Terraform/libvirt |
| public Istio gateway | `10.77.0.20` | kube-vip |
| TLS-passthrough Istio gateway | `10.77.0.21` | kube-vip |
| other `LoadBalancer` Services | `10.77.0.22-10.77.0.39` | kube-vip cloud-provider allocator |
| dynamic VM DHCP leases | `10.77.0.100-10.77.0.199` | Terraform/libvirt |

Terraform validates that every declared address belongs to the network, that static addresses are unique, and that the Service allocator and dynamic DHCP ranges cannot overlap static infrastructure or each other. Each Kubernetes node defaults to 12 vCPU, 24 GiB RAM, and an 80 GiB disk. The 4 GiB bastion, 1 GiB load balancer, and nodes consume 77 GiB in total. The bastion also has a separate 100 GiB data disk for Docker, Forgejo, Harbor, and the verified seed payload. This reserves enough allocatable capacity for a singleton Big Bang deployment to reschedule local-volume workloads during serial node upgrades.

For the local profile, Atum passes the active target's access settings into Terraform explicitly. Terraform owns the libvirt dnsmasq service and emits one `atum.test` wildcard rule for the public gateway plus sorted exact rules such as `keycloak.atum.test` for the passthrough gateway. The internal libvirt domain remains `atum.local`; it is independent from the application domain.

The CLI, not Terraform, owns workstation resolver integration. It points the workstation's routed `atum.test` domain at the Terraform-owned DNS server without editing `/etc/hosts`. Standalone remote Terraform modules have no local-access settings, receive no local DNS Terraform variables, and perform no workstation resolver integration.

Inspect, install, or remove only the workstation integration with:

```sh
atum infra access status
atum infra access install
atum infra access uninstall
```

Installation writes the reported systemd-resolved drop-in and the
distribution-specific `atum-test-ca.crt` trust anchor after validating the
in-cluster public CA. Uninstall removes only exact Atum-managed files. A
successful local apply verifies wildcard and passthrough DNS, the `.20` and
`.21` ingress addresses, certificate validity, and host trust before printing
application URLs. Standalone remote Terraform modules never prompt for
workstation access.

Kubespray installs Cilium only. The overlay enables kube-proxy replacement, native routing with auto direct node routes, BPF masquerading, dynamic BPF map sizing, and Cilium bandwidth manager. NodeLocal DNS is disabled so Big Bang network policies allow DNS through the CoreDNS Service instead of a link-local node cache. The local overlay pins the Cilium operator and CoreDNS to one replica for the current singleton platform shape while keeping the replica knobs explicit for HA overlays. This local network is a single L2 segment so direct node routes work without a tunnel fallback.

Node cloud-init applies the kernel modules, sysctls, file and locked-memory limits, systemd service limits, and virtio disk queue tuning during first boot before Kubespray runs.
It installs and enables containerd for the Kubernetes nodes; the matching Kubespray inventory selects containerd rather than Docker as the CRI.

When Atum supplies a lock-bound seed payload, Terraform verifies its SHA-256 and reconciles Forgejo at `http://10.77.0.9:3000` and Harbor at `http://10.77.0.9:32443` as ordinary Docker Compose services on the bastion. Their images are loaded from the payload, so deployment does not pull mutable image tags. This private HTTP configuration is limited to the isolated local libvirt network. `terraform destroy` removes the bastion domain and its root/data volumes along with every other VM, cloud-init volume, and the Atum network.
