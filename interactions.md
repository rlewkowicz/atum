# Deployment Interactions and Current State

This record separates the current deployment path from earlier investigations.
The platform is healthy after a normal Flux update. One source-unchanged
destroy/deploy remains as the final reproducibility proof.

## Current state

The latest fresh infrastructure and cluster lifecycle used:

```text
./atum pull updates
./atum destroy --force --keep-bastion
./atum --raw deploy
```

Terraform retained only the bastion, recreated the load balancer and three
cluster nodes, and attached one raw data disk per node. Kubespray installed
Kubernetes `1.35.4` with its default Calico CNI and completed with
`failed=0` and `unreachable=0`. All three control-plane nodes are Ready.

Flux bootstrap bound the cluster to the seed Forgejo `main` branch. Atum
directly applied only Flux's SOPS age-key Secret. Ordinary Flux reconciliation
then made all eight Kustomizations and all 32 HelmReleases Ready, including Big
Bang, its generic OpenSearch packages, certificate gates, and the typed Atum
operator configuration. No platform object was patched and no forced
`flux reconcile` command was used.

The fresh run also proved that the raw data-disk handoff corrected the earlier
shared API latency failure. GitLab completed its initial migration and install;
CloudNativePG, metrics-server, and the Flux controllers did not reproduce the
cross-package restart cascade. Harbor and GitLab had bounded startup-only
restarts while their databases and migrations became ready, then stabilized.

The source tree changed during that run to codify the final Fluent Bit finding.
The platform itself reached Ready, but Atum correctly rejected the stale local
publication receipt. A subsequent normal `atum platform apply` published the
exact source and Flux rolled Fluent Bit on its native two-minute child-release
cadence. The remaining validation is therefore a source-unchanged fresh
destroy/deploy, not another live repair.

## OpenSearch integration boundary

This was not a native Big Bang Elasticsearch failure. Atum intentionally
replaces the built-in Elasticsearch package with OpenSearch as a Big Bang
generic package. That preserves Big Bang and Flux ownership of the child
releases, but it means Atum must supply the small integration surface that Big
Bang's built-in Elasticsearch templates normally derive.

The selected deployment uses the official OpenSearch and OpenSearch Dashboards
charts and official immutable images at chart/application tuple `3.8.0/3.8.0`.
There is no OpenSearch application source build, OpenSearch operator, custom
resource, or Atum-authored workload manifest.

Three Atum-authored integration values caused the observed churn:

1. Fluent Bit originally used
   `opensearch-cluster-master.opensearch.svc.cluster.local`. With Kubernetes'
   `ndots:5`, that four-dot name was tried through search-suffixed forms before
   the absolute lookup. During startup pressure, CoreDNS forwarding timed out
   and Fluent Bit reported:

   ```text
   getaddrinfo(host='opensearch-cluster-master.opensearch.svc.cluster.local',
   err=4): Domain name not found
   no upstream connections available
   ```

   The supported cluster-local name is now the short
   `opensearch-cluster-master.opensearch`.

2. Native OpenSearch HTTPS was enabled, but the official chart's port `9200`
   retained its default Service port name `http`. Istio protocol detection
   consequently sent the encrypted stream through the plaintext/passthrough
   path. The evidence included `PassthroughCluster` traffic and client
   certificate failures even though the issuing CA and SANs were correct.
   Setting the chart's supported `service.httpPortName: https` makes Envoy use
   the known outbound OpenSearch service while OpenSearch continues to own TLS,
   authentication, users, roles, and role mappings.

3. Fluent Bit's OpenSearch output defaulted to a `512000`-byte HTTP response
   buffer. One node retained five filesystem chunks because the bulk response
   exceeded that limit:

   ```text
   cannot increase buffer: current=512000 requested=544768 max=512000
   http_do=-1 URI=/_bulk
   failed to flush chunk ... retry ...
   ```

   Both OpenSearch outputs now use the documented Fluent Bit
   `Buffer_Size 1M` setting. After Flux updated the Big Bang-generated child
   values Secret, the child HelmRelease detected the changed config on its
   ordinary interval and rolled all three DaemonSet Pods. The node with the
   retained files then reported:

   ```text
   flush backlog chunk '...' succeeded
   ```

   All five previously stuck chunks drained immediately. The new Pods are
   Ready with zero restarts and show no buffer, DNS, TLS, or flush errors.

These are bounded generic-package integration values, not patches to Big Bang,
the live cluster, or the OpenSearch chart. Each is documented with evidence
and a removal condition in `platform/docs/overrides.md`.

## Package and ownership ledger

| Boundary | Current interpretation |
| --- | --- |
| Terraform | Owns the libvirt network, machines, load balancer, raw node data volumes, and mounts needed before Kubespray. |
| Kubespray | Owns Kubernetes `1.35.4`, Calico, CoreDNS, API authentication/OIDC, etcd, containerd, and the selected storage directories. |
| Flux | Owns every platform Kubernetes object, SOPS decryption, Big Bang, child releases, certificates, and the Atum operator. |
| Big Bang | Owns package composition. OpenSearch, Dashboards, and cert-manager remain Big Bang generic packages rather than independent bootstrap releases. |
| OpenSearch | Official chart/application `3.8.0/3.8.0`, native HTTPS and security plugin enabled, with official images delivered through Harbor. |
| Atum operator | Owns only the closed `PlatformIdentityConfiguration` provider state for declared Keycloak and Vault objects. Flux owns its Kubernetes resources and desired custom resource. |
| Calico | Kubespray's default CNI is deployed. The evaluated downloads map selects only the files and images needed by the canonical Calico/containerd inventory; disabled CNI, runtime, cloud, and addon artifacts are not published. |
| Kubespray artifacts | Atum verifies the exact local cache and live bastion/Harbor targets before Ansible. Nodes use Kubespray's native per-node checksum-verified downloads from `10.77.0.9:8080`; no workstation listener, temporary firewall opening, controller cache, rsync, SCP, or node OCI bundle participates. |
| Strict policy | Big Bang's Istio and NetworkPolicy controls remain enabled. The OpenSearch service port is captured by Istio, and cross-namespace Fluent Bit access uses exact service-account and workload selectors. |

## Earlier investigations, condensed

An early deployment selected Cilium without a platform requirement and
overrode Big Bang's global webhook ingress too narrowly. That denied
cross-node admission traffic. The override was removed and Kubespray's default
Calico selection restored.

NodeLocal DNS was tested after forwarded-name timeouts, but Big Bang's default
DNS policy selects CoreDNS rather than the link-local host-network cache. The
test was removed. Kubespray again owns two CoreDNS replicas and uses its
documented TCP upstream forwarding option for the Terraform-owned dnsmasq
endpoint.

The first full startup overloaded etcd and containerd on copy-on-write qcow2
root disks. Metrics Server, CloudNativePG, and Flux lost API connectivity, and
GitLab's interrupted first install later presented its generic unsupported
upgrade message because no successful initial revision existed. Terraform now
provides raw data disks; Kubespray places etcd and containerd beneath the
mounted path. The next clean run completed GitLab's initial install without
that failure.

The Keycloak provider briefly made the intended administrator password usable
before assigning its management role. An interruption could therefore leave a
valid but under-authorized account returning HTTP `403`. The typed provider now
assigns the role before completing the credential handoff. It does not adopt
arbitrary users or add a fallback identity.

The public and passthrough gateway VIP path required the selected
`externalTrafficPolicy: Local` and kube-vip per-Service election behavior.
Kubespray owns IPVS strict ARP; Flux and the gateway charts own the Services.
No host route or live Service patch remains.

The original OpenSearch source build was based on comparing a selected chart
with a different application image whose binary rejected rendered webhook
arguments. That comparison did not prove a source build was necessary. The
updater now selects and validates the official chart/application tuple and
fails with attributed render evidence if an official image is incompatible.

## Final completion criteria

The platform is complete when one final source-unchanged lifecycle proves:

- Terraform, Kubespray, Flux bootstrap, Big Bang, all child HelmReleases,
  certificate gates, and `PlatformIdentityConfiguration` reach their native
  Ready conditions without a forced reconcile or live patch;
- restart counts stabilize and logs show no API stall, CrashLoopBackOff,
  repeated probe failure, OpenSearch transport failure, or Fluent Bit backlog;
- anonymous Kubernetes API access is limited to the selected health and
  bootstrap paths, while discovery and resource paths remain rejected;
- OIDC and selected application authentication flows work with the declared
  claims and provider-owned objects;
- OpenSearch native TLS, certificate verification, authenticated roles, strict
  mesh transport, and indexed log growth are all observed; and
- local publication, delivery, Flux reconciliation, DNS, and CA-trust
  exactness pass together.
