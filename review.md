# Architecture Level-Set Review

Review date: 2026-08-27

Status: **The control-plane direction is correct, but the current
`actionplan.md` is not ready to enter Final Validation.** The staged
implementation still contains an unused OpenSearch operator and source build,
several security and Cilium compatibility overrides that need bounded evidence,
and documentation that contradicts the intended Flux passthrough boundary.

## Review basis

This review covers the current staged worktree and the following governing
documents:

- `README.md`
- `AGENTS.md`
- `actionplan.md`
- `CONTRACT.md`

The selected Big Bang source, rather than a sibling checkout alone, is the
authoritative upstream for deployment decisions:

- Big Bang version: `3.31.1`
- selected commit: `b9a49842b930b4e5706265d26867ee7f0ba79d5b`
- selected tree:
  `.atum/cache/upstreams/full/bigbang/b9a49842b930b4e5706265d26867ee7f0ba79d5b`

`../bigbang` also reports chart version `3.31.1`, but it is at commit
`3315ba7688828924b8dbe0a5f7f22c43d53db032`. It is useful for exploration, but
it is not interchangeable with the selected tree. Package and wrapper findings
below are based on the exact commits hydrated beneath `.atum/cache`.

The most relevant upstream material reviewed was:

- Big Bang chart values, schema, templates, values guide, GitOps workflow,
  generic-package deployment guide, network-policy guidance, and package
  integration guidance;
- the selected Big Bang wrapper chart and its `PeerAuthentication` template;
- the selected Vault, GitLab, Headlamp, Monitoring, Garage, Fluent Bit,
  CloudNativePG, and other enabled package documentation, with focused review
  of every meaningful manual or post-install runtime instruction;
- the selected Kubespray offline generator;
- the OpenSearch, OpenSearch Dashboards, and OpenSearch operator chart archives
  and operator sources; and
- the Go operator project layout and generation guidance in `../operator-sdk`.

No implementation, generated state, or existing staged file was changed as part
of this review.

## Executive conclusion

The desired handoff should be stated as follows:

1. Terraform owns infrastructure, including the libvirt network, machines,
   volumes, cloud-init, and dnsmasq configuration.
2. Ansible/Kubespray owns Kubernetes, including the API-server configuration,
   Cilium installation and configuration, node lifecycle, and cluster upgrades.
3. Flux owns every Kubernetes object that constitutes platform desired state,
   including SOPS decryption, Big Bang, Big Bang child releases, certificates,
   and the Atum operator.
4. Big Bang owns package composition. Its built-in and generic package
   `HelmRelease` objects are not independently managed by Atum.
5. The Atum CLI owns validation, publication, upstream invocation, observation,
   cross-plane ordering, and local workstation integration. Its only direct
   Kubernetes apply is Flux's SOPS age-key Secret.
6. The Atum operator owns only explicitly declared provider objects that the
   selected charts cannot express, currently a closed Keycloak/Vault identity
   contract. Flux still owns the operator's Kubernetes resources and custom
   resource.

The current normal Flux path follows this boundary:
`cli/platform/flux.go:20-139` checks Flux, runs `flux bootstrap git`, binds
Forgejo `main`, and projects the SOPS identity. It does not patch Big Bang or
call `flux reconcile`. That is correct.

The raw Flux command at `cli/command/platform_command.go:126-136` is also
correct. It preserves the promised system-binary passthrough. An explicit
operator command such as:

```sh
atum platform flux reconcile source git flux-system
atum platform flux reconcile kustomization bigbang --with-source
atum platform flux reconcile helmrelease bigbang -n bigbang --with-source
```

does not make Atum a reconciler. It asks the applicable Flux controller to
refresh or reconcile Git-declared state. `reconcile source git` specifically
requests a source fetch; the Kustomization and HelmRelease commands request
their owning controllers to act on declared state. In every case Flux remains
the lifecycle owner.

The selected Big Bang documentation itself recommends
`flux reconcile source git bigbang` and
`flux reconcile helmrelease bigbang -n bigbang` in
`docs/concepts/git-ops-workflow.md:240-253`. This agrees with the official Flux
command documentation for
[GitRepository](https://fluxcd.io/flux/cmd/flux_reconcile_source_git/),
[Kustomization](https://fluxcd.io/flux/cmd/flux_reconcile_kustomization/), and
[HelmRelease](https://fluxcd.io/flux/cmd/flux_reconcile_helmrelease/).

The correct restriction is narrower:

> Normal `atum apply` must not patch platform resources, implement a second
> reconciliation path, or depend on forced reconciliation to manufacture
> success. Explicit raw Flux passthrough is allowed because Flux's controllers
> remain authoritative.

## Ownership map

| Concern | One authoritative owner | Atum's permitted role | Prohibited split |
| --- | --- | --- | --- |
| libvirt network, machines, volumes, dnsmasq | Terraform | invoke, pass inputs, observe native result | Ansible, Flux, or ad hoc host mutation authoring the same resources |
| Kubernetes nodes, API server, Cilium, cluster upgrade | Kubespray/Ansible | derive bounded inputs, invoke, observe | Flux/operator/CLI rewriting cluster configuration after Kubespray |
| Git source refresh and Kubernetes platform state | Flux controllers | bootstrap Flux, publish source, raw passthrough, observe conditions | CLI patches, Jobs, post-Flux Ansible, or a second desired-state repository |
| Big Bang child package composition | Big Bang | supply documented values and generic-package declarations | standalone Atum releases for Big Bang children |
| Package workloads and package-local policy | selected chart/controller | express documented values and validate the final render | Atum-authored workload copies or indefinite post-render patches |
| Keycloak and Vault provider objects absent from chart APIs | narrowly typed Atum operator | publish the typed desired custom resource through Flux | CLI API calls, generic actions, scripts, Jobs, or arbitrary provider URLs |
| SOPS ciphertext and decryption | SOPS and Flux | bounded projection; apply only the bootstrap age-key Secret | custom crypto or imperative application of decrypted platform Secrets |
| local DNS, CA trust, and host permissions | Atum CLI | install/remove only Atum-owned workstation artifacts | Terraform provisioners or platform controllers mutating the workstation |

## Findings

### F-01 — High: the OpenSearch operator and its source build are unused

`platform/apps/bigbang/values.yaml:257-265` enables the OpenSearch operator.
The ordinary OpenSearch chart at `platform/apps/bigbang/values.yaml:266-328`
deploys OpenSearch directly as its own StatefulSet and declares only a
`dependsOn` edge to the operator at lines 313-315. A repository-wide search
finds no `OpenSearchCluster` custom resource or any other consumer of the
operator CRDs.

The updater then turns this unused package into a material supply-chain branch:

- `cli/update/source_builds.go:12-75` resolves the operator source and forces a
  source build;
- `platform/build/docker/Dockerfile.delivery:7-29` builds the manager binary;
- `platform/build/docker-bake.hcl:149-165` publishes it;
- `platform/apps/bigbang/generated-values.yaml:474-484` injects the image;
- `atum.json`, `atum.lock.json`, and
  `platform/docs/finalpackages.md:79,242` track it.

This violates the goal to vendor and build as little as possible. It also adds
CRDs, a controller, RBAC, a namespace, a wrapper, a sidecar, an image, a chart,
and another readiness edge without owning any required platform state.

Required correction:

- remove `packages.opensearch-operator`;
- remove OpenSearch's dependency on that release;
- remove its chart selection and source-build special case from the updater;
- rerun `atum pull updates` so the generated values, desired state, lock,
  build graph, and package report lose the operator atomically; and
- retain the normal OpenSearch and Dashboards charts.

This is preferable to selecting a different operator chart. If a future design
actually declares an `OpenSearchCluster`, chart/image compatibility must be
re-evaluated at that point.

### F-02 — High: `actionplan.md` is no longer an executable plan

`AGENTS.md:53-73` requires concrete phases, affected files, exact actions and
locations, risks, and post-cleanup work. `actionplan.md` currently contains only
Summary, Scope, Architecture, a stale Problem statement, and Final Validation.

The Problem at `actionplan.md:39-44` still says the tree contains the old
all-node bundle, in-cluster receipts, standalone cert-manager, identity Jobs,
and post-Flux Ansible reconciliation. The staged cutover has removed or replaced
those mechanisms. Meanwhile, the issues found in this review have no
implementation phases at all.

Starting `actionplan.md:46-62` would validate a design known to contain an
orphan controller/build and unresolved security exceptions. The plan must be
reworked before execution. Suggested remaining phases appear at the end of this
review.

### F-03 — High until proven: OpenSearch security relies entirely on the mesh,
but the final mesh invariant is not yet demonstrated

The generic-package wrapper is justified. The selected Big Bang generic-package
guide says the wrapper provides sidecar injection and `PeerAuthentication`, and
that its default is STRICT mTLS
(`docs/installation/environments/extra-package-deployment.md:173-183,230-232`).
The selected wrapper template confirms the default:

```yaml
spec:
  mtls:
    mode: STRICT
```

This means the wrapper is the upstream-supported way to give a community
OpenSearch chart the same service-mesh transport posture used by integrated Big
Bang packages. It is not inherently over-patching.

The application values nevertheless make the mesh the only security boundary:

- Fluent Bit sends plaintext HTTP with `tls Off` in
  `platform/apps/bigbang/values.yaml:20-40`;
- OpenSearch disables both demo setup and the OpenSearch security plugin in
  `platform/apps/bigbang/values.yaml:319-323`;
- Dashboards uses an HTTP OpenSearch endpoint in
  `platform/apps/bigbang/values.yaml:329-343`; and
- access is intended to be constrained by an Istio authorization policy and a
  Kubernetes NetworkPolicy at lines 274-312.

That can be a valid Big Bang-style design: application containers speak HTTP,
while injected sidecars establish strict mTLS on the wire. It is valid only if
the exact final render proves all of the following:

1. the OpenSearch, Dashboards, and Fluent Bit namespaces and pod templates
   receive the intended sidecars;
2. a namespace- or workload-scoped `PeerAuthentication` selects OpenSearch and
   is `STRICT`;
3. the OpenSearch service port is captured by the mesh, with no unmeshed bypass;
4. the authorization policy selects the actual OpenSearch pod labels and allows
   only the intended Fluent Bit service account on port 9200;
5. the NetworkPolicy selects the same actual labels and source pods; and
6. health checks, init containers, and controller traffic still function under
   strict mode.

If any of these are not true, OpenSearch is unauthenticated because the native
security plugin is disabled. The fix is then either to correct the
upstream-supported wrapper values or enable native OpenSearch authentication
and TLS. It is not to add an imperative patch or another controller.

Two related values must not be described as strict mTLS:

- `KC_HTTPS_CLIENT_AUTH=request` at
  `platform/profiles/local/prep/values.yaml:159-184` requests, but does not
  require, a client certificate; and
- the seed Harbor endpoint is intentionally private-network HTTP
  (`atum.json:594-595` and
  `infra/libvirt/scripts/reconcile-seed-plane.sh:114-117`), which is why
  `platform/apps/bigbang/helmrelease.yaml:20-31` adds `spec.insecure: true` to
  Big Bang's otherwise inexpressive OCI `HelmRepository`.

Those are explicit local-profile exceptions outside the claim of strict
workload-to-workload mesh mTLS. They should remain visibly scoped as such.

### F-04 — Medium: the Cilium mode is legitimate, but CIDRs and NetworkPolicy
post-renderers are broader than the documented need

Cilium is unambiguously the selected CNI:

- `kube_network_plugin: cilium` and `kube_proxy_remove: true` are set at
  `orchestration/inventory/atum/group_vars/k8s_cluster/k8s-cluster.yml:6-7`;
- Cilium `1.19.4` and its runtime settings are at lines 26-64; and
- `policyCIDRMatchMode: nodes` is set at lines 48-55.

The node-aware CIDR mode is a defensible Kubespray-owned setting. Cilium's
[node CIDR policy documentation](https://docs.cilium.io/en/stable/security/policy/layer3/#selecting-nodes-with-cidr-ipblock)
explains that it allows ordinary Kubernetes `ipBlock` selectors to match node
identities, which is needed when self-hosted API servers are reached through
node addresses. It has a small policy-map cost and version-sensitive behavior;
for example, the later
[Cilium issue 47827](https://github.com/cilium/cilium/issues/47827) reports a
wildcard-node matching regression in newer 1.19 patch releases. The selected
1.19.4 predates the reported affected patch level, but the setting still needs
an explicit upgrade check.

The problems are in the policy inputs built around it:

- `networkPolicies.controlPlaneCidr` is `10.77.0.8/29` at
  `platform/profiles/local/prep/values.yaml:1-6`. Big Bang documents this as the
  Kubernetes API endpoint range and recommends a `/32` for a single endpoint.
  The local API VIP is `10.77.0.10`, so the destination can be
  `10.77.0.10/32`.
- The same `/29` is also reused as the ingress source definition for webhook
  traffic at lines 10-15. API destination identity and control-plane node
  source identity are different concepts and should not share one broad value
  merely because their addresses are adjacent.
- `networkPolicies.vpcCidr: 10.77.0.0/24` at lines 7-9 is documented upstream
  for Vault access to private AWS KMS/S3 endpoints. The local target has no such
  endpoint, so this appears to be an irrelevant broad allowance.
- The `postRenderers` anchor at lines 16-33 patches Gluon wait-job
  NetworkPolicies for Kyverno Policies, Kiali, Headlamp, and Istio Gateway. It
  directly edits package-owned policy because Cilium does not treat `0.0.0.0/0`
  as matching node identities in this mode.

The post-renderer may be a real compatibility patch, but it currently conflicts
with `CONTRACT.md:118-121,263-265`, which says package charts own policy
rendering and Atum does not reimplement reachability. Retain it only with:

- the exact rendered policy and failed traffic path it corrects;
- the exact packages and Cilium versions that need it;
- the narrow node source addresses required, preferably explicit `/32` entries;
- a removal condition tied to the upstream package or Cilium behavior; and
- a final render test proving the patch still targets a real resource.

Do not simply replace every `/29` with one `/32`: first separate API egress
destination, webhook ingress sources, and wait-job node access into their actual
sets. The goal is narrower ownership, not a blind CIDR edit.

### F-05 — Medium: the Atum operator is narrow in behavior, but only partially
uses the Operator SDK project model

The current runtime boundary is substantially sound:

- `operator/api/v1alpha1/platformconfiguration_types.go:13-20` defines a closed
  Keycloak/Vault spec;
- endpoints and Secret names are fixed by the controller rather than exposed as
  arbitrary execution inputs;
- there are no scripts, generic actions, manifests, plugin names, or arbitrary
  provider URLs in the custom resource;
- `platform/apps/atum-operator/configuration.yaml:6-105` declares only
  administrator, group, scope, client, Vault auth, policy, role, and external
  group intent; and
- the controller owns only provider objects and native status/finalizer
  behavior.

This is not currently a sloppy catch-all. The risks are structural:

1. `PlatformConfiguration` is a generic name that invites unrelated provider
   tasks to be added later. `PlatformIdentityConfiguration` or similarly
   bounded naming would make the admission boundary clearer.
2. The repository has controller-runtime types and Kubebuilder markers, but no
   Operator SDK `PROJECT`, scaffolded operator `config/` source, or operator
   Makefile generation targets.
3. `platform/apps/atum-operator/crd.yaml:27-170` is hand-maintained while
   `operator/internal/controller/platformconfiguration_controller.go:336-395`
   repeats much of its validation at runtime. Those parallel schemas can drift.

The local `../operator-sdk` project layout documentation identifies `PROJECT`
as the project configuration and uses `make generate` and `make manifests`
with `controller-gen` for Go operators. “Based on Operator SDK” should mean
adopting that scaffold and generation contract, not importing or vendoring the
Operator SDK repository into Atum.

Required correction:

- add the minimal Go Operator SDK/Kubebuilder project metadata and pinned
  generation workflow;
- make Go markers the schema/RBAC source where the tools support the rule;
- generate CRD/RBAC manifests deterministically for the Flux platform layer;
- keep only genuinely cross-field or provider-runtime checks in controller
  validation; and
- keep the custom resource closed to identity/provider objects.

A single closed identity CR is reasonable. Separate CRDs are necessary only if
future provider domains have truly independent lifecycles; do not introduce
generic task machinery to avoid that decision.

### F-06 — Medium: “manual upstream work becomes operator work” needs an
admission rule

The intent is good but the literal rule is too broad. Upstream documentation
uses “manual” for development tests, upgrades, backup/restore, break-glass
repair, Vault initialization/unseal, credential rotation, DNS, and environment
prerequisites. Those are not all reconciliation requirements.

A documented manual step is eligible for the Atum operator only when every
condition below is true:

1. it is required for Atum's steady-state baseline;
2. the target is provider/service API state, not infrastructure, Kubernetes,
   Helm, a workload, a certificate, a Secret projection, or a local host;
3. the exact selected chart cannot express it through values, realm import,
   native custom resources, or another upstream controller;
4. the desired state can be represented by a narrow typed schema without
   scripts, generic maps, arbitrary URLs, or commands;
5. reconciliation is idempotent and has explicit ownership, status, deletion,
   retry, and secret-custody semantics; and
6. the operator can observe readiness through provider APIs without inventing a
   parallel platform lifecycle.

The selected Vault package provides a valid example. Its `docs/keycloak.md:1-4`
explicitly says Big Bang does not automate Vault SSO, then documents Keycloak
client creation and Vault auth-method, policy, role, and group mapping through
provider APIs. Those are appropriate typed operator objects.

The selected GitLab package is the counterexample. Its
`docs/overview.md:29-32` says application-side SSO is entirely configuration as
code with no manual post-install step. Those values belong in Big Bang. Only
the corresponding Keycloak client, if no selected Keycloak chart API or realm
import owns it, belongs in the operator.

Vault `autoInit.enabled: true` at
`platform/apps/bigbang/values.yaml:128-132` is also explicitly a local/dev
choice. The selected Vault production guide recommends a deliberate production
unseal design. Initialization, root-token custody, backup, and unseal must not
silently expand the operator's scope.

#### Selected manual-work coverage

A scan of the exact selected package Markdown found the following meaningful
runtime manual-work categories. Generated README warnings, package development
procedures, release maintenance, and test instructions were excluded because
they do not describe deployed platform state.

| Selected upstream instruction | Actual owner | Current Atum coverage or gap |
| --- | --- | --- |
| Vault `docs/keycloak.md` — create a Keycloak client/group mapping and Vault OIDC auth method, policy, role, and group alias | Atum operator provider contract | Correct operator scope. The current typed Keycloak/Vault intent covers these object classes. |
| Headlamp `docs/keycloak.md:64-180` — create the public PKCE client, groups scope/mapper, and documented Headlamp-specific token attributes | Atum operator for required Keycloak objects | The current operator creates the client and groups scope/mapper, but it does not declare the documented `headlampId` mapper or per-user attribute. Prove those are unnecessary for the exact selected Headlamp version; if required, add only a specifically typed Headlamp claim contract. |
| Headlamp `docs/keycloak.md:196-223` — configure Kubernetes API OIDC | Kubespray | Already projected into the Kubespray API-server authentication configuration. This must never move into the operator. |
| Headlamp group-to-Kubernetes permission binding | Big Bang/Flux values and Kubernetes RBAC | Currently expressed in identity values. The `cluster-admin` grant is an explicit local authorization policy, not operator work. |
| Monitoring `docs/KEYCLOAK.md:9-73` — create Grafana, Prometheus, and Alertmanager clients and applicable scopes/mappers | Atum operator for required Keycloak objects | The clients and shared groups mapper exist. The selected Atum values use standard `profile`, `email`, and `groups` claims rather than the guide's named Grafana scope. Prove that exact claim set against the rendered applications; add only missing typed mappings, not a generic mapper map. |
| Monitoring `docs/KEYCLOAK.md:75-187` — configure Grafana, Prometheus, Alertmanager, Authservice, CA, and chains | Big Bang values and SOPS-backed values | Already chart-facing configuration. The upstream example's `kubectl create secret` is replaced by Flux/SOPS, not by the operator. |
| Big Bang wrapper guide — configure Authservice chains and label protected workloads | Big Bang generic-package and application values | The OpenSearch Authservice chain and Dashboards label are values. No provider API or operator work is involved. |
| GitLab `docs/overview.md:29-32` — no manual application-side SSO action when values are correct | Big Bang values; Atum operator only for the Keycloak client | Current ownership split is correct. |
| Garage `docs/credential-rotation.md:1-237` — manual blue/green S3 consumer-key rotation and consumer restart | SOPS desired state, Garage chart lifecycle, Flux, and an explicit operational procedure | This is a destructive, multi-party credential-rotation workflow, not baseline reconciliation. Do not turn it into an operator task or let the operator restart workloads. The chart already automates admin-token propagation through Big Bang. |
| Vault `docs/production.md` — initialization, unseal/KMS setup, and operational token custody | Vault operational design plus infrastructure/secret owners | Not operator scope. The current `autoInit` setting is a local-only shortcut. |
| CloudNativePG recovery guide — create a replacement cluster from backup because recovery is not in-place | CloudNativePG custom resources/controller and an explicit recovery procedure | Not operator scope and not part of baseline apply. |
| Fluent Bit output configuration | Big Bang/package values | The package intentionally leaves output selection to Big Bang/site values. OpenSearch output is not operator work. |
| Package upgrade, backup, restore, credential rotation, break-glass, and troubleshooting commands | owning upstream tool/controller and explicit operations | Remain human-administered procedures or raw upstream passthrough. A word such as “manual” does not transfer resource ownership. |

The Headlamp and Monitoring rows are the two unresolved provider-configuration
coverage questions. Resolve them by testing the exact selected clients and
tokens against the selected applications. Do not preemptively add a generic
Keycloak mapper vocabulary: either a documented typed claim is required, or no
new operator API should be added.

### F-07 — Medium: Kubespray artifact delivery is authoritative but not minimal

The selected inventory uses Cilium, yet the desired delivery graph contains 86
Kubespray-scoped images, including Calico, Flannel, MetalLB, Hubble, and other
disabled alternatives.

This is not an Atum ownership fork. The selected Kubespray
`contrib/offline/generate_list.sh:12-27` intentionally extracts all downloads
from `roles/kubespray_defaults/defaults/main/download.yml`, and its README says
it produces all images from that file. Atum is following the official upstream
offline discovery path.

It is nevertheless inconsistent with the broader “publish only what this
cluster uses” goal. The resolution should be explicit:

- prefer an official Kubespray inventory-aware offline discovery interface if
  one exists for the selected release;
- do not add a hand-maintained Atum allowlist that reimplements Kubespray's
  image logic; and
- if upstream exposes only the full list, document that the 86-image set is an
  accepted air-gap correctness/safety tradeoff rather than claiming a minimal
  runtime payload.

### F-08 — Medium: the Kubespray OIDC comment claims a nonexistent ownership
handoff, and anonymous authentication is undecided

`orchestration/inventory/atum/group_vars/k8s_cluster/k8s-cluster.yml:13-17`
claims a “post-platform owner” will replace the API-server authentication file
with its CA-bearing form.

The code does something better and different:

- `cli/orchestration/platform_oidc.go:78-104` refuses the initial Kubespray
  handoff unless the root CA is already available, then includes that CA in the
  JWT authenticator; and
- `cli/orchestration/execution.go:257-305` passes the complete projection to
  Kubespray, which owns the mounted file and API-server flag.

No post-platform replacement path was found. The comment therefore describes a
split owner that does not exist and contradicts the three-plane contract. It
should be corrected to describe the one Kubespray handoff.

The same projection sets anonymous authentication to enabled with no
conditions. That may be needed for Kubernetes health endpoints, but the current
documents do not say so. Decide the final Kubernetes policy before the
Kubespray handoff and encode it once; do not promise a later Flux/operator
transition.

### F-09 — Medium: build policy is mostly evidence-based, but the README states
a looser rule

There are currently nine build targets:

- the first-party Atum operator;
- Garage init helper;
- Grafana with pinned offline plugins;
- three Kubectl helper variants required by rendered wait jobs;
- the OpenSearch operator source build;
- the PostgreSQL compatibility image used by Harbor/Keycloak subcharts; and
- the Vault image with its rendered curl lifecycle requirement.

`platform/docs/finalpackages.md:263-279` records rendered command, filesystem,
or lifecycle evidence for the compatibility builds. These are not automatically
architectural violations. Each non-first-party build should retain exact
evidence and a removal condition so a future compatible upstream chart/image
can replace it.

Removing F-01 leaves eight targets: one first-party image and seven bounded
compatibility/offline-content builds. No OpenSearch application binary is built.

`README.md:17` instead says images are built “where there is no analog or the
upstream was sunset.” That is too permissive and contradicts
`AGENTS.md:437-455` and `CONTRACT.md:300-327`, which require exact rendered
compatibility evidence. A sunset or missing Iron Bank analog alone is not a
reason to build; an official vendor image should be mirrored whenever it
satisfies the rendered contract.

### F-10 — Medium: the governing documents contain several direct
contradictions or stale claims

| Document and location | Problem | Required correction |
| --- | --- | --- |
| `AGENTS.md:393-394` | Blanket “Do not call `flux reconcile`” conflicts with raw upstream passthrough at `AGENTS.md:486-488`, with `README.md:143-146`, and with upstream Big Bang operations guidance. | Forbid automated repair/parallel reconciliation in normal apply; explicitly permit user-requested raw Flux reconcile commands. |
| `CONTRACT.md:356-361` | Blanket `flux reconcile` ban makes invocation itself look like ownership, contrary to `CONTRACT.md:123-133`. | Apply the same narrower distinction between normal apply and explicit controller invocation. |
| `CONTRACT.md:448-449` | “Explicit reconciliation beside normal Flux reconciliation” is ambiguous enough to prohibit the supported Flux CLI. | Name the actual violation: a second reconciler, imperative mutation, alternate source, or apply path outside Flux. |
| `CONTRACT.md:118-121,263-265` | Says Atum does not own package NetworkPolicy behavior, while the local profile directly post-renders four package policies. | Remove unnecessary patches; for necessary compatibility patches, define exact rendered evidence, narrow scope, and removal condition. |
| `README.md:17` | Allows builds based only on absence/sunset. | State the official-image-first, rendered-contract evidence rule without rewriting the README's voice. |
| `README.md:18` | “Nothing is vendored” is broadly true, but the repo packages selected charts into Harbor and contains compatibility build material. | Keep the concise claim if desired, but avoid using it to imply there are no maintained compatibility artifacts. |
| `README.md:167-173` | Advertises Velero commands although the selected Big Bang default is disabled and Atum does not enable it. | Remove the nonfunctional quickstart section or enable and fully design Velero; minimal scope favors removal for now. |
| `actionplan.md:39-44` | Describes mechanisms already removed by the staged cutover. | Replace with the unresolved problems in this review. |
| `actionplan.md:46-62` | Final Validation is the only remaining phase, contrary to `AGENTS.md:53-73`. | Add concrete remediation phases before Final Validation. |

## OpenSearch chart and application version analysis

### What the mismatch means

The selected independent chart set is:

| Component | Chart version | Declared app version | Assessment |
| --- | --- | --- | --- |
| cert-manager | `v1.21.1` | `v1.21.1` | aligned |
| OpenSearch | `3.8.0` | `3.8.0` | aligned |
| OpenSearch Dashboards | `3.8.0` | `3.8.0` | aligned |
| OpenSearch operator | `2.8.2` | `2.8.0` | versions differ and this tuple is functionally incompatible |

Chart and application versions are independent by Helm design. The selected Big
Bang integration guide explicitly notes that they need not match
(`docs/community/development/package-integration/upstream.md:69-77`).
Different numbers alone are therefore not a defect.

This particular operator release is defective as published:

- operator chart `2.8.2` declares `appVersion: 2.8.0`;
- its Deployment defaults the manager image tag to `2.8.0`;
- the chart passes `--enable-webhooks` and `--webhook-port`;
- the published `2.8.0` binary does not define those flags; and
- the flags appear in the `2.8.2` source.

The binary exits during flag parsing with an unknown-flag error before the
controller starts. That is what “Docker Hub's 2.8.0 image rejected the chart's
webhook flags” means.

The source build at `2.8.2` repairs the immediate publisher mismatch, but
`cli/update/source_builds.go:14-17` draws the wrong general conclusion when it
says the chart version is the authoritative runtime version. A chart version is
not normally an application version. Compatibility must be established from
the chart's rendered command and a real published image or exact source tag.

### What the selector currently does

`cli/update/chart_resolution.go:142-176,230-268` does not literally select the
latest stable application and then derive a chart. It:

1. walks stable chart releases in version order;
2. reads each chart's metadata;
3. rejects a semantic `appVersion` that contains a prerelease; and
4. accepts the newest Kubernetes-compatible chart whose app version is not a
   semantic prerelease.

Opaque app versions are accepted because Helm permits them. The algorithm
therefore selected operator chart `2.8.2`, the newest chart in the eligible
window still declaring stable app `2.8.0`. It did not detect that the rendered
arguments were incompatible with that app.

As observed on 2026-08-27:

- the normal OpenSearch Helm repository's current stable OpenSearch and
  Dashboards releases are `3.8.0`, matching the selected chart/app tuples;
- newer OpenSearch operator charts exist through `3.0.2`, but they declare
  `3.0.0-alpha` as the application version; and
- the operator registry publishes `2.8.0` and `3.0.0-alpha`, not a stable
  `2.8.2` image.

Relevant upstream evidence:

- [OpenSearch Helm chart releases](https://github.com/opensearch-project/helm-charts/releases)
- [OpenSearch operator releases](https://github.com/opensearch-project/opensearch-k8s-operator/releases)
- [OpenSearch operator image tags](https://hub.docker.com/r/opensearchproject/opensearch-operator/tags)
- [`2.8.0` operator flags](https://github.com/opensearch-project/opensearch-k8s-operator/blob/opensearch-operator-2.8.0/opensearch-operator/main.go)
- [`2.8.2` operator flags](https://github.com/opensearch-project/opensearch-k8s-operator/blob/opensearch-operator-2.8.2/opensearch-operator/main.go)

If the operator were required, chart `2.8.0` plus official image `2.8.0` is the
obvious stable 2.x tuple to evaluate because the old chart does not pass the new
webhook flags. Choosing the newest operator chart would instead adopt an alpha
runtime. Neither choice is needed here because the operator has no consumer.

The recommended result is:

- keep OpenSearch chart/application `3.8.0`;
- keep Dashboards chart/application `3.8.0`;
- mirror their official immutable images;
- remove the operator chart and source build; and
- make future chart admission fail with attributed rendered compatibility
  evidence instead of automatically turning a chart version into a runtime
  source build.

## Values override inventory

The values precedence in `platform/apps/bigbang/helmrelease.yaml:41-78` is
coherent and matches `CONTRACT.md:216-228`:

1. target-independent operational values;
2. updater-generated chart and image projections;
3. local target profile;
4. required SOPS-backed stateful values and scalar `targetPath` injections;
5. optional identity values; and
6. optional CA material.

The layers have distinct owners. That separation should be retained.

### Target-independent operational values

Source: `platform/apps/bigbang/values.yaml`

| Override | Why it exists | Review disposition |
| --- | --- | --- |
| disable Alloy, Loki, NeuVector, and bbctl; enable Fluent Bit | Atum's selected local platform uses Fluent Bit with OpenSearch rather than Big Bang's default observability/security selection | Keep as site package selection, but document why each default-enabled package is removed |
| replace Fluent Bit outputs with OpenSearch stanzas | selected Fluent Bit package's Elasticsearch helper assumes credentials/TLS fields that do not fit the current mesh-only, security-plugin-disabled OpenSearch endpoint | Keep only as a bounded compatibility override; validate exact upstream value shape each update |
| remove Grafana's legacy Angular pie-chart plugin | selected Grafana no longer supports it | Keep while the selected package still emits the legacy setting; attach removal condition |
| enable Authservice, GitLab, Harbor, Headlamp, Keycloak, and Vault | declared platform product set | Keep |
| point GitLab at external CloudNativePG, Redis, and Garage, including dependency edges and KNP intent | avoids bundled database/cache/storage and gives each service one chart/controller owner | Keep; this is real topology, not a patch |
| disable Iron Bank-specific FIPS provider claims in Harbor and Keycloak PostgreSQL subcharts | official PostgreSQL compatibility image does not provide the Iron Bank-only OpenSSL contract | Keep only with the rendered compatibility evidence already tracked |
| enable Vault auto-init | makes the single supported local environment operable | Keep only as an explicitly local/dev posture; do not call it production-safe |
| declare CloudNativePG, PostgreSQL operand, Redis, and Garage generic packages | selected Big Bang release has no native API for this topology | Keep; Big Bang remains their `HelmRelease` owner |
| declare OpenSearch and Dashboards as generic packages | selected Big Bang release has no native OpenSearch package API | Keep |
| enable the OpenSearch wrapper, Istio injection, strict mesh policy, KNP, and Fluent Bit authorization | applies Big Bang's documented generic-package integrations | Keep subject to F-03 render proof |
| single-node OpenSearch, one replica, no chown/sysctl init | minimal local topology and local storage/security constraints | Keep in the local profile if the chart permits; target-independent placement should be reconsidered |
| disable OpenSearch security plugin and use HTTP | relies entirely on strict mesh mTLS and policy | Keep only if F-03 is proven and clearly scoped to local; otherwise enable native security |
| OpenSearch operator package and dependency | no declared operator custom resource consumes it | Remove |

The OpenSearch `singleNode`, replica, persistence-init, and sysctl settings are
currently in the target-independent file at lines 316-327 even though they
describe the constrained local topology. `CONTRACT.md:165-172` assigns local
facts to the target profile. Move them to the local layer unless every future
target is intentionally single-node.

### Updater-generated values

Source: `platform/apps/bigbang/generated-values.yaml`

These are not discretionary site patches. They project:

- the one Harbor OCI Helm repository;
- selected chart names and versions;
- source type;
- internal image repositories and tags; and
- package-specific image value paths discovered from the selected render.

They should only change through `atum pull updates`. The OpenSearch operator
entries at lines 474-484 are incorrect because the operational package is
unnecessary; fix the updater input/logic and regenerate rather than hand-editing
this file.

Big Bang's selected `helmRepositories` API does not expose the Flux OCI
`insecure` field. Because the seed Harbor is intentionally HTTP, the root
HelmRelease post-renderer at `platform/apps/bigbang/helmrelease.yaml:20-31` is a
real selected-upstream API gap. It is a narrowly targeted patch, not a general
post-render convention. It should carry the explicit local-only reason and be
removed if Harbor gains TLS or Big Bang exposes the field.

### Local profile values

Source: `platform/profiles/local/prep/values.yaml`

| Override group | Why it exists | Review disposition |
| --- | --- | --- |
| domain, API/network CIDRs | local libvirt addressing | Keep ownership in profile; narrow per F-04 |
| Kyverno local-path and Harbor registry exceptions | local-path helper pods and private registry are intentional local facilities | Keep narrowly scoped to exact path, namespace, name, and registry |
| Gluon wait-job post-renderers | Cilium node identity does not match the chart's world CIDR | Evidence and narrow per F-04; remove when upstream no longer needs it |
| single replicas and disabled autoscaling | local resource ceiling | Keep in local profile |
| Metrics Server `--kubelet-insecure-tls` | Kubespray kubelets use self-signed serving certificates and no second certificate reconciler is desired | Explicit local exception; prefer Kubespray-owned signed kubelet serving certs if upstream supports them |
| Keycloak native HTTPS, certificate mount, hostname, and truststore | provider API and browser endpoint need the platform certificate | Keep; do not describe client-auth `request` as strict mTLS |
| Vault API address | public/local platform identity | Keep |
| Istio gateway VIPs | local libvirt load-balancer addresses | Keep |
| storage sizes, local storage class, and one-node topology | local capacity | Keep |

The profile also grants Headlamp's OIDC group a `cluster-admin` binding through
`platform/profiles/local/prep/identity-values.yaml:67-77`. That is an explicit
authorization decision, not merely SSO wiring. It should be called out as a
local administrative policy rather than hidden in generated-looking identity
values.

### Identity and Secret-backed values

`platform/profiles/local/prep/identity-values.yaml` configures the application
side of SSO for Authservice, GitLab, Harbor, Headlamp, Grafana, Kiali, Policy
Reporter, monitoring, OpenSearch ingress, Keycloak bootstrap, and Vault's CA and
service entry. These are chart-facing values and properly remain in Flux/Big
Bang desired state.

`platform/apps/atum-operator/configuration.yaml` configures the provider side:
Keycloak administrator/group/scope/client objects and Vault auth/policy/role/
external-group objects. That division is correct:

```text
application OIDC settings ── Big Bang values ──► application releases
provider OIDC objects ───── typed Atum CR ─────► Keycloak and Vault APIs
```

The stateful Secret layer supplies credentials and Garage scalar values through
native Flux `targetPath` merging. It does not duplicate topology and is aligned
with the contract.

## Strict mTLS interpretation

“In line with Big Bang” should mean using the same security invariant, not
copying ECK/Elastic-specific values:

```text
selected chart workload
  + Big Bang wrapper/namespace integration
  + Istio sidecar injection
  + PeerAuthentication STRICT
  + package-specific AuthorizationPolicy
  + package NetworkPolicy
```

If that invariant works for an integrated Elastic package, it can also protect
OpenSearch. The exact chart still matters because labels, ports, probes, init
containers, and sidecar injection points differ. Therefore, “it works for ELK”
is design evidence for the mesh pattern, not proof that an OpenSearch render is
correct.

Application TLS and mesh mTLS are separate:

- plaintext HTTP between application containers is acceptable only when the
  sidecars capture the path and enforce strict mTLS on the wire;
- native HTTPS without required client authentication is server-authenticated
  TLS, not mutual TLS; and
- ingress TLS, provider API TLS, registry TLS, and mesh mTLS are distinct
  boundaries and should be documented separately.

No Atum operator behavior is needed to achieve this. Big Bang values, its
wrapper, Istio, and the selected package policies own the result.

## Document-by-document assessment

### `README.md`

Aligned:

- the three-plane description at lines 22-33;
- the SOPS age-key Secret exception at lines 101-104;
- thin raw upstream commands at lines 129-147; and
- the selected-state and Harbor/Forgejo workflow.

Needs targeted correction:

- line 17's broad build criterion;
- explicit indication that raw Flux reconcile commands are legitimate
  controller requests, while normal apply remains declarative;
- the stale Velero quickstart at lines 167-173; and
- a link to the bounded provider/operator scope once documented.

The author-written overview and voice do not need a rewrite.

### `AGENTS.md`

Aligned:

- lines 367-385 define the three owners and SOPS exception correctly;
- lines 405-416 preserve upstream ownership and a narrow provider operator;
- lines 431-455 require updater ownership and evidence-driven image decisions;
- lines 472-478 keep OpenSearch and cert-manager under Big Bang generic
  packages; and
- lines 486-488 require raw system-binary passthrough.

Contradiction:

- lines 393-394 forbid all `flux reconcile` calls. Replace that with the
  normal-apply/explicit-passthrough distinction above.

Missing boundary:

- add the operator admission rule from F-06 and the Operator SDK
  generation/source-of-truth requirement from F-05.

### `CONTRACT.md`

Aligned:

- lines 31-61 define the three planes and one direct Secret exception;
- lines 70-121 give a coherent handoff and owner map;
- lines 137-176 separate desired, resolved, generated, operational, and target
  facts;
- lines 178-228 select one exact Big Bang source and minimal values;
- lines 300-327 define official-image-first build admission;
- lines 332-354 describe the intended apply order; and
- lines 393-419 constrain the provider operator.

Contradictions or ambiguity:

- lines 359-360 and 448-449 over-broaden the Flux reconcile prohibition;
- lines 118-121 and 263-265 do not admit or bound the current NetworkPolicy
  post-render compatibility patches;
- strict mesh mTLS versus native application TLS is not stated, allowing
  “strict mTLS” to be claimed without proving the selected workload is actually
  in the mesh; and
- `PlatformConfiguration` is described as narrow, but no admission rule
  prevents future unrelated manual tasks from accumulating there.

### `actionplan.md`

The Summary, Scope, and Architecture point in the correct direction. The plan
should retain that ownership model.

The Problem and remaining work do not match the staged tree or this review.
Final Validation must not begin until implementation phases address F-01
through F-10.

## Recommended remaining action-plan phases

The action plan should be rebuilt with concrete files, locations, risks, and
post-cleanup work for these phases:

1. **Governing ownership and security contract**
   - correct the Flux reconcile language in `AGENTS.md` and `CONTRACT.md`;
   - correct the Kubespray OIDC handoff comment and decide anonymous auth;
   - state the operator admission rule and strict-mesh invariant;
   - make targeted README corrections, including Velero and build policy.
2. **OpenSearch simplification**
   - remove the unused operator package, dependency, source-build selector,
     build stage, bake target, and managed-file expectations;
   - rerun the updater to remove every generated operator coordinate and
     artifact;
   - retain official OpenSearch/Dashboards 3.8.0 charts and images.
3. **Minimal Big Bang values and network policy**
   - move local OpenSearch topology to the local profile;
   - separate API destination and control-plane source CIDRs;
   - remove irrelevant `vpcCidr` use;
   - remove or precisely evidence each wait-job post-renderer;
   - document removal conditions for compatibility overrides.
4. **Typed Operator SDK boundary**
   - adopt the minimal Go Operator SDK/Kubebuilder project and generation
     structure;
   - generate CRD/RBAC from canonical markers;
   - eliminate parallel hand-maintained schema where generation can own it;
   - keep the CRD restricted to Keycloak/Vault identity provider state.
5. **Artifact minimization**
   - record a removal condition for every remaining compatibility build;
   - decide whether an official inventory-aware Kubespray offline path can
     replace the current all-download list without reimplementing Kubespray.
6. **Final Validation**
   - run only after the implementation phases have independently completed;
   - render and inspect the exact Big Bang graph, including strict OpenSearch
     mesh selection and every remaining post-render patch;
   - prove all charts/images resolve through Harbor and all platform objects
     reconcile through Flux;
   - verify normal apply performs no direct platform mutation beyond the SOPS
     age-key Secret;
   - verify raw `atum platform flux reconcile ...` remains a transparent
     upstream command; and
   - perform the repository's complete configured generation, formatting,
     lint, static analysis, pure-Go build, test, deployment, and cleanup flow.

## Final disposition

The fundamental architecture does not need another control plane or a broader
operator. It needs subtraction and sharper boundaries:

- Flux reconciliation, including user-requested `flux reconcile`, remains Flux
  ownership.
- The Atum CLI remains a thin invocation, publication, observation, sequencing,
  and workstation-integration layer.
- The OpenSearch operator and its source build should be deleted because no
  operator custom resource exists.
- OpenSearch itself should remain the official 3.8.0 chart and image, protected
  by Big Bang's documented strict-mesh integration.
- Cilium stays under Kubespray; broad CIDR and post-render exceptions must be
  narrowed and proven rather than normalized as permanent Atum policy.
- The Atum operator remains a typed Keycloak/Vault provider reconciler and
  should adopt Operator SDK generation conventions without becoming a generic
  manual-work engine.

That is the shortest path back to the stated handoff goal.
