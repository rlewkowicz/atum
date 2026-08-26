# Atum Architecture Contract

This document defines Atum's desired architecture. Code, generated state, and
documentation converge on these stable ownership, lifecycle, security, and
integration boundaries. Selected versions, commits, image digests, and package
counts belong in resolved state and generated package documentation, not here.

## Product boundary

Atum is a greenfield, local-first continuity layer around system-installed
Terraform, Ansible/Kubespray, Flux, SOPS, and upstream Big Bang. No Atum
platform currently exists. Atum therefore has no data, topology, image,
package-path, or secret-schema migration contract and preserves no prior
runtime compatibility state. Unsupported old input is rejected; current state
is generated directly.

Ordinary future upstream selection and the required Kubespray
minor-version ladder remain supported. They are atomic applications of current
desired state, not transformations of an earlier Atum platform.

The only supported end-to-end target is local libvirt. `infra/vultr` remains an
independent Terraform module, not an advertised Atum platform target. A remote
target may be added only when reachable source, registry, domain, network,
trust, and workstation-continuity handoffs have a single explicit owner.

Atum accepts site intent, selects and pins exact upstream inputs, prepares
local host credentials and engine connections, invokes each upstream engine,
and reports native conditions plus Atum-owned receipts. It does not reproduce
the engines it coordinates.

## Control-plane ownership

There are exactly three deployment control planes:

- Terraform owns infrastructure.
- Kubespray/Ansible owns Kubernetes.
- Flux owns everything deployed into Kubernetes as platform state.

Atum validates inputs, publishes the exact repository and artifacts, invokes
those control planes in order, and observes their native conditions. It does
not create, patch, or reconcile platform workloads alongside Flux. Platform
identity and service connections that selected charts cannot express through
values are expressed through the narrowly typed Atum operator described below;
they are never an imperative Atum handoff.

`platform/` is the monorepo representation consumed by Flux from the exact
`main` branch of this repository on the bastion seed Forgejo instance.
Cluster directories compose infrastructure controllers and the platform in
dependency order. Big Bang is delivered as its official Helm chart through a
Flux `HelmRelease`; Atum supplies site intent through values layers and uses
only the minimum Kustomize resources or patches needed to compose those native
objects.

SOPS-encrypted Kubernetes Secret manifests live in a cluster-specific
subdirectory beneath `platform/` on that same branch. A Flux
`Kustomization` references the subdirectory through the root `flux-system`
`GitRepository`, decrypts it, and applies it before dependent platform values
are rendered. No alternate platform branch, secondary desired-state
repository, imperative workload apply, or parallel reconciliation path is
permitted. The one imperative Kubernetes object is the SOPS decryption-key
Secret required by Flux itself.

Harbor is the delivery authority for every image used by Kubernetes,
Kubespray, Flux, or a platform workload and every Helm chart used by the
cluster. Runtime reconciliation never fetches a chart or image from an
upstream registry. The sole exception is a minimal bastion-only seed payload
that Terraform uses to start Forgejo and Harbor before Harbor exists. That
payload is not cluster desired state and is never copied to cluster nodes.

## Ownership handoffs

```text
site intent
└─ atum pull updates
   ├─ exact immutable lock
   ├─ generated delivery projections
   └─ minimal Big Bang values
      └─ Harbor artifacts and Forgejo main
         └─ Flux bootstrap
            └─ Flux reconciliation
               ├─ Big Bang
               │  ├─ built-in package HelmReleases
               │  └─ generic package HelmReleases
               │     ├─ cert-manager
               │     └─ OpenSearch
               ├─ cert-manager HelmRelease health gate
               │  └─ issuer and Certificate resources
               └─ Atum operator after certificate readiness
                  └─ typed Keycloak and Vault provider state

SOPS document
└─ bounded Atum projection
   └─ SOPS-encrypted manifests beneath platform/
      └─ Forgejo main
         └─ Flux decryption and reconciliation
            └─ profile preparation
               ├─ package input Secrets
               └─ final Big Bang values Secret
```

Each arrow is one handoff. The sender owns input validation and custody until
the transfer. The receiver owns execution and physical resources afterward.

- Terraform owns infrastructure resources and state.
- Ansible/Kubespray owns Kubernetes node and cluster configuration.
- Flux owns source and Kustomization reconciliation.
- Big Bang owns child source and release composition, package value
  propagation, and public dependency conventions.
- Each package chart, operator, or controller owns its resources and
  conditions.
- Flux owns the Atum operator's Kubernetes resources and the declared
  `PlatformConfiguration` custom resource. The operator owns only the typed
  Keycloak and Vault provider state and its provider-facing status conditions.
- Official SOPS owns encrypted-file format and cryptography.
- Atum owns local host integration, bounded secret projection, immutable
  publication receipts, and cross-plane sequencing.

Atum may validate a handoff it authors. It must not reimplement Helm
truthiness, Big Bang package identity, NetworkPolicy reachability, workload
rollout rules, PVC semantics, controller state machines, or source-controller
readiness.

## System tools

Terraform, Ansible/Kubespray, Flux, SOPS, and other declared tools are external
capabilities. Atum locates and validates the configured binary, establishes
the working directory and environment, and forwards raw arguments after its
phase or action boundary.

Atum may add only arguments required for an Atum-owned handoff, such as an
exact inventory or state path. It does not reinterpret arbitrary upstream
flags, silently replace a selected binary, install a missing prerequisite, or
mutate live resources through an alternate ad hoc path.

Every Atum build and Go test uses `CGO_ENABLED=0`.

## Desired, resolved, and generated state

`atum.json` contains disjoint ownership regions:

- human-owned fields express the local target, policy, permitted upstream
  locations, and other site intent;
- updater-owned fields express the selected candidate, discovered package and
  image obligations, generated delivery policy, and other derived facts.

`atum pull updates` preserves human-owned fields and atomically replaces only
updater-owned regions. `atum.lock.json` is the sole immutable resolution
record. Generated values, Flux manifests, source references, build metadata,
and `platform/docs/finalpackages.md` are projections of the selected source
trees and lock.

Build output digests and registry publication results are publication facts,
not immutable resolution. One mode-0600 receipt lives only in ignored
`.atum/state/publication.lock.json`, bound to the exact desired hash, root-lock
hash, source snapshot and commit, image and chart publication identities, and
minimal seed identity. A missing or stale receipt is repaired by rerunning the
explicit delivery operation; delivery never rewrites tracked resolution
state.

The updater is the sole writer of coupled upstream coordinates, digests,
desired derived fields, lock state, generated platform values, generated Flux
manifests, and build identities. If output is wrong, fix the updater and rerun
it. Do not hand-edit a coupled projection.

Human-authored platform files have narrower roles:

- operational Big Bang values own target-independent package enablement and
  genuine application topology;
- the local profile owns domain, CIDRs, registry endpoints, storage class,
  load-balancer addresses, and other local facts;
- one explicit generic-package declaration owns coordinates for a package the
  selected Big Bang release does not integrate.

Generated image values project resolved internal targets only. They do not
select packages or carry application intent. Markdown is never parsed as
configuration.

## Upstream selection and Big Bang

Normal update selects exactly one newest stable Big Bang tag, commit, and
source tree. The local `../bigbang` checkout is an authoritative development
reference but is not selected merely because it exists. Candidate values,
schema, templates, package metadata, documentation, charts, and render
observations must all come from the exact selected tree.

If that candidate cannot satisfy Atum's handoff or supply-chain policy, update
fails with attributed evidence. It never silently falls back to an older Big
Bang release. An explicitly requested historical commit is a separate exact
selection.

Big Bang operational values use the selected release's one public values
shape. If it exposes unified `packageConfiguration.version: v1`, Atum uses
that shape directly. Otherwise it uses only that release's public path. Atum
does not support both shapes concurrently or run an upstream values converter.

Values are minimal:

- package enablement or disablement;
- site-required application topology;
- documented cross-package endpoints and dependency edges;
- security intent not already owned by an upstream default;
- minimal generic-package declarations.

For the selected stable Big Bang release, cert-manager and OpenSearch are
generic packages because that release has no native package APIs for them.
Their exact charts are packaged and published to Harbor, and Big Bang owns
creation of their Flux `HelmRelease` objects. They are not standalone
bootstrap releases, independent Flux roots, or Atum-reconciled workloads.

Operational values contain no Atum metadata, copied CI fixture, package
coordinate duplicate, empty image placeholder, local target fact, or secret.
Big Bang tests are evidence for Big Bang, not a production deployment API.
Post-renderers and wrappers are not composition defaults. Use a supported
official chart and its public values first.

The Big Bang HelmRelease loads values in explicit precedence:

1. target-independent operational values;
2. updater-generated source and image projections;
3. local profile values;
4. required SOPS-backed platform values;
5. optional identity or certificate projections.

The one platform-values Secret stores Garage credentials as scalar keys.
Native Flux `targetPath` merges inject those scalars into the single
operational Garage consumer declaration, so the secret layer does not repeat
or own bucket topology. The Garage chart still creates and owns its consumer
Secret.

## Platform services

GitLab consumes independently owned PostgreSQL, Redis, and S3-compatible
object storage. It does not deploy or own them.

```text
CloudNativePG operator ──► PostgreSQL ──┐
Redis chart ────────────────────────────┼─► GitLab
Garage chart ───────────────────────────┘
SOPS-backed Big Bang values ───────────► GitLab-local Secrets
```

The selected Big Bang package owns the CloudNativePG operator release. The
official CloudNativePG cluster chart is the sole declarative owner of one
PostgreSQL `Cluster`. CloudNativePG owns operand commands, reconciliation,
Services, PVC lifecycle, and conditions. There is no PostgreSQL wrapper,
post-rendered `Cluster`, Atum workload manifest, or CloudNativePG PostgreSQL
operand compatibility build. PostgreSQL images rendered by distinct selected
Harbor or Keycloak subcharts are independent obligations; the final render's
command, filesystem, UID/GID, and lifecycle evidence decides whether each can
be mirrored directly or requires a minimal compatibility build.

The selected Redis chart owns its release, workload, Service, persistence, and
input Secret. The selected Garage chart owns its release, persistence,
initialization lifecycle, buckets, administration input, and consumer
credentials. GitLab never receives Garage administration material.

Required service material is deterministically derived once from SOPS-owned
root material. Profile preparation creates only inputs that must exist before
a release. Big Bang's documented GitLab production values create GitLab-local
database, Redis, object-storage, and Rails Secrets from the final secret-backed
values layer. Kyverno does not copy, transform, or rotate these credentials.

Big Bang and package charts own NetworkPolicy rendering. Atum expresses only
documented cross-package connection intent and validates its authored inputs;
it does not evaluate resulting Kubernetes connectivity.

## Secret authority

One current typed secret schema is accepted. Any other schema version or
malformed document fails without mutation. The configured SOPS document is the
durable secret authority. A mode-0600 ignored local document is an explicit
development override with the same schema.

`cli/secrets` owns typed decoding, validation, root generation, deterministic
HKDF domain separation, narrow projections, and prompt clearing of plaintext
buffers. Official `sops` owns encryption, decryption, recipient handling,
metadata, and encrypted-file compatibility.

The canonical identity contract contains public realm, administrator identity,
group, endpoint, and client intent only. Administrator, bootstrap, and
confidential-client credentials are independently derived from the SOPS-owned
identity seed; no login password is tracked as identity configuration.

The SOPS adapter uses bounded stdin and stdout without a shell, plaintext
argument, plaintext temporary file, or command transcript. Missing SOPS is a
preflight prerequisite error. Secret plaintext never enters logs, desired or
lock state, tracked values, generated ConfigMaps, build arguments, or Git
history.

Atum renders the bounded Secret projections only as SOPS-encrypted manifests
beneath the cluster's `platform/secrets` directory. They are committed and
published with the exact platform source, and the declarative platform graph
owns one Flux `Kustomization` for that directory. Profile preparation depends
on its Ready condition. `flux bootstrap git` owns creation of the
`flux-system` namespace and controllers. After bootstrap, Atum directly
applies only the age decryption-key Secret required by Flux; Flux decrypts and
applies the platform Secrets. Profile preparation derives only the required
package input Secrets and final Big Bang values Secret.

## Images and builds

One final render observation discovers source, release, and runtime image
obligations. Independently sourced charts may be rendered at that same
boundary when the Big Bang root render cannot expose their images. Each public
image maps once to:

- an immutable official vendor image and digest mirrored internally; or
- one minimal reproducible compatibility build whose necessity is proven by
  the selected chart's rendered command, arguments, filesystem paths, UID/GID,
  and lifecycle.

One canonical desired image record owns policy and compatibility evidence.
One lock record owns immutable resolution. One generated value projects the
internal runtime target. No historical baseline, duplicate crosswalk, build
profile copy, or transition record participates.

Iron Bank image references are non-fetchable compatibility evidence only.
Atum never creates a Registry1 client, mirrors an Iron Bank artifact, uses one
as a build base or material, or delivers one. Official upstream images are
inspected directly. A new package is admitted from the final candidate render
without requiring a historical image list.

CloudNativePG uses official immutable operator and PostgreSQL operand images.
The operator owns the operand command and lifecycle. A compatibility build for
a separately rendered PostgreSQL subchart, Redis, or helper remains only when
the final rendered chart proves a vendor-image filesystem or script mismatch.
Unrendered and redundant build stages are deleted.

Publication binds exact source and image receipts before Flux source
admission. Delivery compliance is a separate observation from reconciliation.

## Apply and status

The local apply sequence is linear:

1. validate desired and resolved state and required tools;
2. load SOPS material and prepare bounded projections;
3. ask Terraform to apply local infrastructure;
4. publish the lock-bound repository state only to the seed Forgejo `main`
   branch and publish every cluster image and chart to Harbor;
5. ask Ansible/Kubespray to configure Kubernetes;
6. ask `flux bootstrap git` to install only Flux and bind it to Forgejo
   `main`;
7. directly apply only Flux's SOPS age-key Secret;
8. wait for normal Flux reconciliation to decrypt the platform source and
   deploy Big Bang;
9. let the generated Big Bang Kustomization establish one native readiness
   condition from ordered health checks on the root Big Bang and its
   Harbor-backed generic cert-manager `HelmRelease`;
10. let the dependent Flux Kustomization reconcile and wait for only its owned
    issuer and Certificate resources;
11. wait for the Flux-deployed Atum operator to finish its typed Keycloak and
    Vault provider configuration;
12. reconcile explicit local DNS and CA integration.

Atum owns ordering, cancellation, error attribution, and its receipts. It
performs small safe cleanup for a failed short handoff when possible;
otherwise it leaves an inspectable state and an idempotent rerun path. It does
not mutate live resources manually to manufacture success, call
`flux reconcile`, activate a deployment branch, or retain an in-cluster Atum
receipt object.

The explicit local-access install command uses the same native platform status
and delivery-compliance observation as the automatic apply path. Missing
kubeconfig, incomplete or failed Flux reconciliation, or incomplete delivery
compliance terminates before either workstation DNS or CA trust is changed.
Infrastructure-only apply invokes Terraform without installing or verifying
workstation access.

Kubespray planning observes only the live API-server Kubernetes version and
the exact committed release ladder. An existing cluster must match one ladder
entry, and each observation may select only the next exact entry; unavailable,
newer, skipped, or unlisted versions terminate without mutation. Atum retains
no orchestration receipt, resume checkpoint, or durable configuration hash.
A direct user-requested Kubespray apply may reconcile the current exact target,
with native health checks and an in-memory input-consistency check confined to
that invocation.

Flux and package/controller `Ready` or failure conditions own reconciliation
completion. Atum does not install Flux twice or infer completion from
Deployments, StatefulSets, DaemonSets, Pods, PVCs, Jobs, replica counts,
package-name heuristics, or reconstructed child release sets.

Status presents separate dimensions:

- native Flux, Helm, and owning-controller conditions;
- Atum-owned source, image, and publication compliance receipts;
- Atum-owned local DNS and CA receipts.

An Atum compliance discrepancy does not rewrite a controller's lifecycle.
Runtime digest drift may be reported as bounded delivery diagnostics.

## Host and provider continuity

Terraform owns the local libvirt network, machines, volumes, cloud-init, and
dnsmasq. Terraform does not elevate privileges or mutate workstation DNS,
trust, firewall, or libvirt authorization through provisioners.

Atum may explicitly install, report, and remove only its own local libvirt
permission, forwarding, systemd-resolved, and CA-trust artifacts. Interactive
authorization transfers the user's real terminal to the canonical host
`sudo`; a TUI line is never treated as a password prompt.

Prefer official chart OIDC values, realm imports, and client declarations.
When the selected Keycloak and Vault charts cannot express required
service-internal configuration, one Flux-deployed Atum operator reconciles a
narrowly typed `PlatformConfiguration`. The custom resource contains only
declared Keycloak and Vault intent plus fixed Secret references; it cannot
carry arbitrary URLs, scripts, manifests, plugins, actions, or generic
execution maps.

Flux owns the operator deployment, RBAC, CRD, credential and CA Secrets, and
singleton custom resource as Kubernetes desired state. The operator owns only
the matching provider objects, their idempotent lifecycle, and its native
`ObservedGeneration`, `KeycloakReady`, `VaultReady`, and `Ready` conditions.
It does not own Kubernetes workloads, Helm releases, certificates,
infrastructure, API-server configuration, or Atum receipts. Reconciliation
Jobs, identity receipt objects, identity API calls from the CLI, identity
Ansible playbooks, and imperative post-Flux handoffs are prohibited.

## Repository and documentation

Upstream directories are replaceable read-only inputs. The exact pinned
Kubespray offline scripts may create their own transient output inside an
ignored hydrated checkout while running; Atum removes that output before the
workflow returns. Atum supplies synthesized offline variables from a unique
mode-`0600` invocation directory beneath `.atum/`, removes that directory as
soon as the official discovery process returns, and retains only
content-pinned files beneath `.atum/`.
Atum does not modify `../bigbang`, `../kubespray`, or hydrated package source,
and does not vendor whole upstream repositories. If a minimal chart must be
vendored, it belongs under `platform/charts`.

`platform/docs/finalpackages.md` is an updater-generated factual snapshot of
the exact selected lock and render: package versions, official chart/project
sources, licenses, enabled functions, and mirror or compatibility-build
decisions. It has no selection authority.

## Prohibited ownership splits

The following are architectural violations:

- compatibility paths for a prior Atum platform;
- normal Big Bang fallback or mixed selected-source semantics;
- hand edits to updater-owned coupled state;
- parallel renderers or package identity vocabularies;
- copied Big Bang CI topology or defaults;
- deployment branches, secondary desired-state repositories, or explicit
  reconciliation beside normal Flux reconciliation;
- any cluster image or Helm chart fetched outside Harbor;
- standalone cert-manager or OpenSearch reconciliation outside their Big Bang
  generic package `HelmRelease` objects;
- reconciliation Jobs or in-cluster Atum receipt objects;
- wrappers, post-renderers, or workload manifests where an official chart
  provides the resource;
- multiple credential generators or secret-copy controllers;
- custom SOPS cryptography;
- plaintext secrets in tracked or observable paths;
- Iron Bank fetch, mirror, build material, or delivery;
- Atum implementations of upstream package, policy, workload, or controller
  semantics;
- synthetic readiness that can override native controller conditions;
- cloud platform claims without complete remote continuity;
- coordinators, flags, registries, or adapters retained only to synchronize
  two owners.
