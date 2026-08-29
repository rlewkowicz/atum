<p align="center">
  <img src="assets/atum.png" alt="Atum" height="500">
</p>

---
Atum is a declarative Go CLI for deploying the Department of Defense (War?) platform [The Big Bang](https://github.com/DoD-Platform-One/bigbang) without access to their Iron Bank images.
---
<p align="center">
  <img src="assets/diagram.png" alt="Arch" height="500">
</p>
<br>

# It's Just a Fancy Wrapper

Big Bang is a platform in a box. The deployment model is open source and openly licensed, but access to its specialty images is restricted. This repo handles a few things on that front. But it's still just a wrapper around battle-tested software platforms. So if something goes wrong, you're not troubleshooting Atum, you're troubleshooting industry-standard, production-proven deployment platforms.

1. All images are swapped out for immutable official upstreams when they satisfy the selected chart's rendered contract. A bounded compatibility image is built from official project source only when the rendered command, filesystem, identity, or lifecycle proves it necessary.
2. It's all fully declarative. Big Bang itself is a Helm chart of Helm charts. Selected charts are repackaged into Harbor rather than vendored wholesale; the repo maintains only the bounded compatibility material and minimal Flux/Kustomize wiring needed to deliver them.
3. As of this writing, it uses Kubespray for the cluster. Lean into it. Own the cluster. I may add support for cloud-native Kubernetes implementations in the future, but this handles upgrades and deployment using Ansible with Mitogen. I'm also out of money in a big way.
4. It's air-gap ready. It publishes every selected cluster image and chart to [Harbor](https://github.com/goharbor/harbor), while a minimal bastion seed starts Harbor, [Forgejo](https://forgejo.org/), and a private repository for the exact checksum-pinned files Kubespray selected.

# Infra, Orchestration, Platform

Converging three planes:

- Terraform-managed infrastructure.
- Ansible/Kubespray-managed Kubernetes.
- Flux-managed Big Bang platform software.

The repository contains the Atum-owned configuration, overlays, compatibility
entrypoints, and build graph. It does not require root `bigbang` or `kubespray`
checkouts. Immutable upstream snapshots are hydrated into the ignored
`.atum/cache` tree from the commits in [`atum.json`](atum.json).
The [identity operator boundary](operator/README.md) documents the narrow
Keycloak/Vault provider state that cannot be expressed through selected chart
values.

### One command, an entire enterprise-grade platform

<p align="center">
  <img src="assets/oneshot.png" alt="Term">
</p>

# Quickstart

```sh
git clone https://github.com/rlewkowicz/atum.git && cd atum
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o atum ./cli/atum
go version -m ./atum
sha256sum ./atum
install -m 0755 atum "$HOME/.local/bin/atum"
atum pull updates
atum secrets init --local
atum secrets render
atum apply
```

### Work in progress

You need a pretty beefy rig to run the local install. It's literally an entire enterprise platform. There are also failure modes I haven't explored. I'm not even certain how the CLI bubbles up errors if you don't have enough resources. I'm polishing the edges, but the base functionality works, and is worth exploring.

## Install

The complete local flow needs Go 1.26+, Terraform, Docker with Buildx/BuildKit,
Python 3.11+, OpenSSH, [SOPS](https://github.com/getsops/sops/releases),
[Flux](https://fluxcd.io/flux/installation/), QEMU/KVM, and system libvirt.
Only local libvirt is supported end to end today.

Atum's preflight tells you which dependencies are missing before it changes
anything.

## Declarative state

[atum.json](atum.json) contains site intent plus updater-owned selected facts.
[atum.lock.json](atum.lock.json) binds that document to exact Git commits,
chart archives, image digests, build inputs, and compatibility constraints.

Review updater output before deployment:

```sh
atum pull updates --check
atum pull updates
git diff -- atum.json atum.lock.json platform
```

## Secrets

For a shared SOPS document:

```sh
atum secrets init --age-recipient age1example...
atum secrets validate
atum secrets render
```

For local development:

```sh
atum secrets init --local
atum secrets validate
atum secrets render
```

Never commit the local file beneath `.atum/`. Rendered Kubernetes Secrets are
SOPS-encrypted under `platform/secrets/<cluster>/`; Flux reads them from this
repo. The SOPS decryption-key Secret is the only imperative cluster object.

## Local host setup

Use these only if your host needs them:

```sh
sudo "$(command -v atum)" infra libvirt permissions install
sudo "$(command -v atum)" infra libvirt forwarding install
```

`--raw` streams the underlying tools. It does not change what `apply` does:

```sh
atum --raw apply
```

`deploy` is an alias for `apply`.

Destroy prompts for the exact response `yes`; `--force` bypasses the prompt:

```sh
atum destroy
atum destroy --force
```

For repeated local validation, retain the seed bastion and its Harbor cache
while Terraform destroys the load balancer and Kubernetes nodes:

```sh
atum destroy --force --keep-bastion
```

The next normal `apply` recreates the cluster and verifies existing immutable
images and charts in Harbor plus retained Kubespray files on the bastion before
publishing anything missing.

## Plane commands

```sh
atum infra plan
atum infra apply
atum infra terraform <terraform-args...>

atum orchestration prepare
atum orchestration inventory
atum orchestration plan
atum orchestration apply --become
atum orchestration upgrade --become
atum orchestration ansible <ansible-playbook-args...>

atum platform prepare
atum platform apply
atum platform status
atum platform flux <flux-args...>
```

## Artifact delivery

```sh
jq -r '.delivery.images[] | [.id, .delivery.default.type, .target] | @tsv' atum.json
atum artifacts publish
```

Full `atum apply` runs that same Forgejo and Harbor publication path
automatically. Kubespray nodes fetch only their selected checksum-pinned files
from the retained private bastion repository; Atum does not open a workstation
listener or copy a controller cache to the nodes. GitLab's PostgreSQL is
managed by CloudNativePG, not a Bitnami PostgreSQL subchart.

## Status

```sh
atum platform status
atum infra access status
```

## More detail

- [Architecture and ownership contract](CONTRACT.md)
- [Selected packages and image decisions](platform/docs/finalpackages.md)
- [Maintained platform overrides](platform/docs/overrides.md)
- [Local libvirt setup](infra/libvirt/README.md)
- [Kubespray patches](orchestration/patches/README.md)
