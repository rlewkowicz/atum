<p align="center">
  <img src="assets/atum.png" alt="Atum" height="500">
</p>

---
Atum is a declarative Go CLI for deploying the Department of Defense (War?) platform [The Big Bang](https://github.com/DoD-Platform-One/bigbang) without access to their "ironbank" images.
---
<p align="center">
  <img src="assets/diagram.png" alt="Arch" height="500">
</p>
<br>

# It's Just a Fancy Wrapper

Bigbang is a platform in a box. The deployment model is opensource, open license. Their specialty images are privileged. This repo handles a few things on that front. But it's still just a wrapper around battle tested software platforms. So if something goes wrong, you're not troubleshooting atum, you're trouble shooting industry standard, production proven deployment platforms.

1. All images are swapped out for their official upstreams, and built from scratch where there is no analog or the upstream was sunset. Their postgres for example relies on bitnami which sunset their public catalog.
2. It's all fully declarative. Bigbang it's self is a helm chart of helm charts. Nothing is vendored to this repo. It's just value overrides.
3. As of this writing it uses kubespray for the cluster. Lean into it. Own the cluster. I may add support for cloud native k8s implementations in the future, but this handles upgrades and deployment using ansible with mitogen. I'm also out of money in a big way.
4. It's airgap ready. It bundles all images into an oci bundle for deployment. It stands up a provisional [harbor](https://github.com/goharbor/harbor)/[forgeio](https://forgejo.org/) combo on the bastion for first time deployment.

# Infra, Orchestration, Platform

converging three planes:

- Terraform-managed infrastructure.
- Ansible/Kubespray-managed Kubernetes.
- Flux-managed Big Bang platform software.

The repository contains the Atum-owned configuration, overlays, compatibility
entrypoints, and build graph. It does not require root `bigbang`, `kubespray`,
or `bitnamilegacy-charts` checkouts. Immutable upstream snapshots are hydrated
into the ignored `.atum/cache` tree from the commits in [`atum.json`](atum.json).

### One command, an entire enterprise grade platform
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
sudo atum apply
```

### Work in progress
You need a pretty beefy rig to run the local install. It's literally an entire enterprise platform. There's also failure modes I've not explored, I'm not even certain how the cli bubbles up errors if you didn't have resources.I'm polishing the edges, but the base functionality works, and is worth exploring. 

## Declarative State

[`atum.json`](atum.json) is the desired-state boundary. It selects the active
infrastructure target, Ansible inventory, supported Kubernetes/Kubespray
ladder, Big Bang and package sources, bootstrap charts, image-delivery policy,
and platform values. [`atum.lock.json`](atum.lock.json) binds that document to
exact source, chart, image, build-graph, and deployment-bundle identities.

Both files are committed. Commands that mutate the cluster reject a stale or
structurally invalid lock. `atum pull updates` changes the desired and resolved
files together through one crash-recoverable transaction. When an update
changes an image or build input, that transaction removes the obsolete image
results and records delivery as pending; the next `atum apply` resolves the
complete delivery and bundle before Terraform can mutate infrastructure.

The selected package topology is documented in
[`platform/docs/finalpackages.md`](platform/docs/finalpackages.md). Operational
and generated Helm values remain separate under `platform/apps/bigbang`; Flux
applies operational values first and exact generated image/source overrides
second.

## Prerequisites

- Go 1.26 or newer to build Atum.
- Terraform on `PATH`.
- Docker with Buildx and a working BuildKit backend.
- Python 3.11 or newer. Atum creates commit-addressed Kubespray virtual
  environments and installs each pinned requirements set itself.
- Ansible/Kubespray host prerequisites, SSH access, and outbound access needed
  to hydrate the immutable source and OCI caches.
- For the local target: QEMU/KVM, system libvirt, and Terraform's libvirt
  provider prerequisites.
- Flux on `PATH` for managed platform reconciliation and the explicit
  `atum platform flux` passthrough.
- Velero on `PATH` only when using `atum platform velero`.

For a production build, disable cgo for a portable static binary, remove local
source paths, and strip the Go symbol and DWARF tables:



Use `go build -o atum ./cli/atum` when local debugging symbols are useful.
`go run ./cli/atum` may replace `atum` in every example.

## Fresh-Clone Deployment

Run the complete convergence directly after cloning:

```sh
atum apply
```

Every command that consumes platform credentials loads the configured age-only
SOPS document and local override. If neither exists, that consumer generates
the complete Forgejo and Harbor credential set in the default plaintext
`.atum/secrets.local.json` file with mode `0600`. The root `/.atum/` directory
is ignored by the committed [`.gitignore`](.gitignore). The deployment TUI
reports the exact path when it creates the file. Creation occurs only on true
absence; decode, decryption, permission, and validation errors are returned
without replacing either file.

Use `atum secrets init --local` only when credentials need to be created before
deployment, and `atum secrets validate` to validate them independently.

For shared environments, create a committed, age-only SOPS document before the
first credential-consuming command. The CLI encrypts it in memory and requires
at least one native age recipient:

```sh
atum secrets init --age-recipient age1example...
atum secrets validate
```

These credentials initialize the Terraform-owned Forgejo and Harbor services
before Flux can reconcile the platform; Flux does not decrypt this file.
Atum reads native age identities from the standard `SOPS_AGE_KEY_FILE`,
`SOPS_AGE_KEY`, or `SOPS_AGE_KEY_CMD` inputs. Never commit
`.atum/secrets.local.json`.

On a dedicated local host, configure the optional libvirt integrations:

```sh
sudo atum infra libvirt permissions install
sudo atum infra libvirt forwarding install
```

The permissions rule grants every local user system-libvirt management, which
is effectively root-equivalent. Omit it when normal group/ACL access is
already configured. The forwarding rule is needed only when the host firewall
blocks traffic from the libvirt bridge.

One command then performs the complete declared deployment:

```sh
atum apply
```

Before a managed workflow changes Terraform state, hydrates Kubespray, invokes
Flux, installs host DNS, or updates CA trust, Atum runs a non-mutating
prerequisite preflight. Only tools required by that command and active target
are probed. Detected versions appear in deterministic dashboard rows; missing
or incompatible requirements are aggregated with their supported override
variable and official installation link. Local-target checks include the
system libvirt connection and KVM, while cloud targets exclude libvirt,
systemd-resolved, kube-vip, and local trust requirements.

On a fresh clone, `atum apply` resolves a pending image delivery or reproduces
an exact missing deployment bundle before creating VMs. Terraform then creates
the infrastructure and reconciles persistent bastion Forgejo and seed Harbor
containers from the verified seed payload. Atum publishes the exact bundle and
source snapshots, derives inventory from Terraform outputs plus the committed
overlay, invokes Kubespray, imports the bundle on every node through Ansible,
and invokes Flux to reconcile Big Bang from the internal sources.

Managed `apply`, infrastructure, orchestration, and platform operations render
a persistent Bubble Tea dashboard styled with Lip Gloss by default.
Infrastructure resources, Kubernetes releases, and platform packages retain
one stable row as they move
from pending through ready; platform rows are derived from `atum.json` and live
Flux/Kubernetes objects rather than a second hard-coded package inventory.
Serial Kubernetes upgrades add per-node rows for cordoning, workload draining,
component upgrade, validation, and uncordoning beneath the active release row.
Terminal-oriented subprocess output and every structured progress transition
are streamed to an exclusive mode-`0600` file beneath `.atum/logs` without
retaining the raw transcript in memory; binary data streams keep their owned
destinations. Non-terminal output uses concise transition lines. To
see the native Terraform, Ansible, and command streams, put the persistent
flag before the phase command:

```sh
atum --raw apply
atum --raw infra apply
atum --raw orchestration upgrade --become
```

The dashboard only observes Terraform output; Terraform remains the sole
owner of infrastructure creation and destruction. Direct `infra terraform`,
`orchestration ansible`, and `platform flux` commands remain native
passthrough boundaries.

The default kubeconfig is
`orchestration/inventory/atum/artifacts/admin.conf`. `KUBECONFIG` may
select another exact cluster when running orchestration or platform commands.

## Plane Commands

Infrastructure commands select `infrastructure.active` from `atum.json` and
pass arguments after the action directly to Terraform:

```sh
atum infra plan
atum infra apply
atum infra destroy
atum infra terraform <terraform-args...>
```

`atum infra destroy` snapshots exact Terraform-managed libvirt identities before
the destroy and returns success only after every domain, network, storage-pool
volume, backing image, and cloud-init disk path is gone. It never removes disks
by a prefix or wildcard.

Use the guarded lifecycle command when removing a complete deployment:

```sh
atum destroy
atum destroy -f
```

Without `-f`, `atum destroy` requires the exact response `yes`. For a local
target it first removes the Atum-owned systemd-resolved drop-in and local CA
anchor, then runs the existing Terraform destroy workflow. It refuses to
remove either host file when its contents are not recognizably Atum-managed,
so a customized file at either path stops the destroy instead of being
overwritten or deleted. Cloud targets skip the workstation cleanup.

Orchestration commands use only the pinned Kubespray caches. Managed install
and upgrade accept option-shaped Ansible arguments while preventing an extra
playbook from crossing the safety boundary. The explicit `ansible` command is
the unrestricted passthrough:

```sh
atum orchestration prepare
atum orch inventory
atum orch plan
atum orch apply --become
atum orch upgrade --become
atum orch ansible <ansible-playbook-args...>
```

Platform commands use read-only Kubernetes observation plus OCI, Forgejo, and
Harbor clients. The system Flux binary owns platform reconciliation and remains
available behind an explicit passthrough boundary:

```sh
atum platform prepare --timeout=25m
atum platform apply --timeout=45m
atum platform status
atum platform flux <flux-args...>
```

`platform` has the `plat` alias and `orchestration` has the `orch` alias.

## Upstream Updates

Resolve the newest stable Big Bang, package, chart, Flux, and Kubespray set that
satisfies the committed Kubernetes compatibility policy:

```sh
atum pull updates --check
atum pull updates
```

To produce a historical installation baseline, pass the exact 40-character
commit of a stable semantic-version Big Bang release:

```sh
atum pull updates 0123456789abcdef0123456789abcdef01234567
```

The pinned form intentionally permits the Big Bang-managed package versions
to move backward and selects the oldest compatible Kubernetes/Kubespray entry
from the committed release floor. It replaces the desired release ladder with
that single baseline. The selected stable Big Bang release or exact commit is
the compatibility authority for its package graph; Atum-owned custom and
bootstrap dependencies still advance to the newest stable release compatible
with that selection. After the baseline is deployed and healthy, the ordinary
no-argument command resolves current upstreams and reconstructs every required
one-minor Kubernetes/Kubespray upgrade step. Arbitrary commits, abbreviated
hashes, prereleases, and commits without a stable release tag are rejected.

The resolver enumerates bounded release catalogs, peels Git tags to commits,
verifies chart archives and Kubespray checksums, renders the exact Flux/Helm
candidate tree, and updates all managed files atomically. It never reads an
ignored root upstream checkout. Run `atum apply` after reviewing the resulting
diff; it resolves any invalidated image outputs and the exact deployment bundle
as part of normal convergence. Commit the resulting desired state, resolved
lock, generated values, and source manifests together.

The selected Big Bang chart also owns transitive support sources such as its
wrapper chart. Atum does not select an independently newer wrapper: it resolves
the repository, tag, chart path, and peeled commit declared by that exact Big
Bang release, snapshots it into the deployment bundle, mirrors it as
`atum-upstreams/wrapper`, and points the generated Big Bang values at the
immutable internal source. Historical Big Bang baselines therefore reproduce
their historical wrapper selection. A moved tag, changed source declaration,
or incompatible rendered wrapper contract rejects that Big Bang candidate;
ordinary updates can fall back to an older compatible stable candidate, while
an exact pinned baseline reports the incompatibility directly.

Autonomous update catalogs exclude prerelease sources. Atum-managed custom and
bootstrap charts also skip stable chart releases whose semantic `appVersion`
is a prerelease. Exact prerelease package or image versions declared by the
selected stable Big Bang release remain authoritative and are preserved. If a
previous custom-chart selection deployed a prerelease application, the next
update may select an older chart carrying the newest stable application to
restore this policy; normal stable selections never move backward.

Atum prefers official publisher images pinned by digest and official Git
sources pinned by exact tag and peeled commit. Upstream chart or source
vendoring is conditional on those pins being insufficient; it is not required
merely because Atum can produce a full source build.

Big Bang wrapper values own Istio authentication, authorization, and
target-side network policy for the standalone OpenSearch namespaces. Fluent
Bit owns its source-side egress. The updater renders and validates those
disjoint policies, their HelmRelease dependencies, and the exact
Fluent Bit-to-OpenSearch TCP 9200 exception before accepting a candidate.
Kustomize remains limited to generated image substitutions and rollout
annotations; it does not duplicate mesh security resources.

Kubernetes upgrades always use `upgrade-cluster.yml`, advance one minor at a
time, and set `serial=1`; independent Ansible host work uses the committed
`orchestration.forks` bound. A durable identity marker records the exact
Kubernetes patch, Kubespray tag and commit, and converged orchestration-input
identity before and after each step. On an already-current Kubernetes release,
`atum apply` runs `cluster.yml` only when the generated host inventory,
declarative orchestration configuration, or tracked Atum-owned orchestration
files differ from that live identity. Atum replays interrupted install/upgrade
checkpoints; it does not adopt an unidentified cluster or downgrade a newer
cluster.

Kubespray customization is confined to
`orchestration/inventory/atum/group_vars`, Atum-owned playbooks, and the
documented patch directory. Upstream roles and root playbooks are immutable
cache inputs.

## Images And Deployment Bundles

The current default `platform` delivery profile contains 79 `linux/amd64`
images: 72 immutable mirrors from official public publishers and seven Atum
builds. The builds are the Grafana plugin layer, PostgreSQL 17 and 18, Redis
8.4 and 8.8, Redis Exporter, and OpenBao compatibility images. Compatibility
builds preserve the runtime contract used by the selected Big Bang chart where
a publisher-native image is not a direct substitute.

No Iron Bank, Bitnami, or Bitnami Legacy image layer is consumed. Their names
in `atum.json` are historical Big Bang cross-reference evidence only. Inspect
the current machine-readable selection with:

```sh
jq -r '.delivery.images[] | [.id, .delivery.default.type, .target] | @tsv' atum.json
```

The full deployment command resolves the selected profile and bundle
automatically. The explicit image commands remain available for build hosts and
registry operators. Build/mirror and publish the selected profile to Harbor:

```sh
HARBOR_USERNAME='<builder>' \
HARBOR_PASSWORD='<password>' \
atum images publish --profile platform
```

When Harbor uses the local Atum CA, also provide its public certificate in
`HARBOR_CA_CRT`. Credentials are read from the environment and streamed to
tools without entering process arguments.

Create the deterministic bootstrap bundle without requiring an existing
cluster or Harbor:

```sh
atum images bundle
```

The builder runs independent transfers concurrently and invokes Bake once for
the selected compatibility graph. BuildKit, Go, Bazel, and package-manager
caches persist beneath `.atum/cache`; unchanged mirror and build results are
reused by exact input hash. The content-addressed bundle and sidecar are stored
under `.atum/artifacts/<lock-sha256>/` and bound into `atum.lock.json`. A
successful resolution removes older generated bundle archives while preserving
the selected bundle and all source/build caches.

`full-build` remains an opt-in profile for source-building every image with a
maintained pinned recipe:

```sh
HARBOR_USERNAME='<builder>' HARBOR_PASSWORD='<password>' \
  atum images publish --profile full-build
```

The canonical committed lock is profile-specific. Re-run the `platform`
publication before a platform deployment after experimenting with
`full-build`.

## Status And Recovery

Require exact bundle, Flux, HelmRelease, pod, source, and runtime-image
readiness. Local status additionally requires the active profile layers, exact
kube-vip releases and gateway VIPs, allocator range, issuers and leaf
certificates, routed DNS, host CA fingerprint, and bounded HTTPS routes:

```sh
atum platform status
```

Inspect or explicitly manage the workstation portion independently:

```sh
atum uninstall
atum infra access status
atum infra access install
atum infra access uninstall
```

The top-level and scoped uninstall commands remove only Atum-managed resolver
and CA files. They do not change the cluster, libvirt dnsmasq configuration,
or any cloud target.

Backup and restore are native Velero operations rather than an Atum-owned live
patching workflow. Arguments after the boundary pass directly to the system
Velero binary:

```sh
atum platform velero backup create platform
atum platform velero backup get
atum platform velero restore create --from-backup platform
```

Velero schedules, storage locations, credentials, and workload policy remain
declarative Big Bang/Flux configuration. Atum does not scale workloads, patch
resources, or perform an imperative restore sequence around the passthrough.

## Local Libvirt Target

The committed local target creates a bastion, an HAProxy API load balancer,
and three control-plane/worker nodes on `10.77.0.0/24`. Each Kubernetes node
defaults to 12 vCPU, 24 GiB RAM, and an 80 GiB disk. Together with the 4 GiB
bastion and 1 GiB load balancer, the target reserves roughly 77 GiB of memory.
Node cloud-init installs containerd, and the committed Kubespray overlay selects
containerd as the Kubernetes CRI; Docker is not installed as a node runtime.

The inventory generator reads Terraform output directly and writes only the
ignored `hosts.yaml` and artifact directory under the selected inventory. It
routes node SSH through the bastion while preserving committed group-variable
overlays. No generated file is written into a Kubespray source tree.

Inspect host integrations and cluster state with:

```sh
atum infra libvirt permissions status
atum infra libvirt forwarding status
atum infra access status
KUBECONFIG=orchestration/inventory/atum/artifacts/admin.conf kubectl get nodes -o wide
```

The local profile routes `atum.test` and `*.atum.test` through the public
Istio VIP at `10.77.0.20`; exact passthrough hosts such as
`keycloak.atum.test` use `10.77.0.21`. kube-vip allocates other
`LoadBalancer` Services from `10.77.0.22-10.77.0.39`. After DNS, ingress,
identity, Kubernetes OIDC, and certificate verification succeed, the managed
TUI finishes with an Access panel. It contains the resolver and CA paths, CA
fingerprint, both ingress VIPs, Keycloak issuer and administrator console,
local-development credentials (`atum` / `atum`), categorized browser
applications, and the token-backed GitLab KAS and registry endpoints. There is
no second terminal summary after the dashboard exits.

Keycloak's master realm is the sole local human-identity authority. The
permanent `atum` user belongs to `atum-admins`, has Keycloak server
administration, and receives the highest supported administrator mapping in
integrated applications. Kubernetes prefixes the group as
`oidc:atum-admins` and binds it to `cluster-admin`, so Headlamp uses native
OIDC instead of a service-account token. Kiali, Grafana, GitLab, Policy
Reporter, Harbor, and OpenBao also use their selected native or reconciled
OIDC integration. Prometheus, Alertmanager, and OpenSearch Dashboards use Big
Bang Authservice because their selected packages do not provide a complete
native browser flow. The derived bootstrap administrator is retired after the
permanent account is verified. GitLab KAS and the registry remain protocol
endpoints whose application-issued tokens are not replaced by browser OIDC.
The per-application integration and administrator matrix is recorded in the
[final package set](platform/docs/finalpackages.md#local-identity-integration-matrix).

## Supported Environment Inputs

Runtime topology and deployment values belong in committed declarative state.
Environment inputs are limited to local executable selection, cluster
selection, decryption, and publication credentials:

- `ATUM_TERRAFORM_BIN`
- `ATUM_DOCKER_BIN` for Docker Engine and its Buildx plugin during delivery
- `ATUM_PYTHON_BIN`
- `ATUM_SSH_BIN` for workflows that execute managed Ansible
- `ATUM_FLUX_BIN`
- `ATUM_VELERO_BIN`
- `ATUM_VIRSH_BIN` for active local-target checks and forwarding actions that
  require live bridge discovery
- `ATUM_FIREWALL_CMD_BIN` for libvirt forwarding actions
- `ATUM_RESTORECON_BIN` for optional SELinux relabeling when selected during
  libvirt permissions installation
- `KUBECONFIG`
- `SOPS_AGE_KEY_FILE`, `SOPS_AGE_KEY`, or `SOPS_AGE_KEY_CMD`
- `HARBOR_USERNAME`, `HARBOR_PASSWORD`, and optional `HARBOR_CA_CRT`

Buildx intentionally has no separate executable override; preflight invokes
the plugin through the validated `ATUM_DOCKER_BIN` identity.

Use `--root` to select another checkout and `--dry-run` to inspect supported
mutations without executing them:

```sh
atum --root /path/to/atum validate
atum --dry-run infra plan
```

## Repository Boundaries

- `cli` owns the Go command and domain services.
- `infra` owns standalone Terraform targets.
- `orchestration` owns inventories, group variables, Atum playbooks, and the
  Ansible overlay—not Kubespray itself.
- `platform` owns the standalone Flux layer and minimal container
  compatibility assets. If chart vendoring becomes unavoidable, the minimal
  chart belongs under `platform/charts`.
- `.atum/cache`, `.atum/artifacts`, `.atum/logs`, `.atum/runtime`, and
  `.atum/state` are ignored, reproducible local data. Preserve
  `.atum/secrets.local.json` separately when intentionally clearing the cache.

Root `bigbang`, `kubespray`, and `bitnamilegacy-charts` directories are ignored
development inputs and are never resolved by Atum code or configuration.
