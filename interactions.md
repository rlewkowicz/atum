# Package Interactions and Current Blockers

This is a snapshot of the deployment at Forgejo revision
`main@sha1:ab5706d5457e93856ccb0a591574a2266c8da91d`. Most of the
visible failures are one admission-control deadlock, not independent package
defects.

## Causal chain

```text
Atum narrowed Big Bang's kubeAPI webhook ingress to 10.77.0.8/29
  -> Cilium presents cross-node API traffic as 10.233.x.x node-router identities
  -> Kyverno's admission endpoint denies the API-server connections
  -> API mutations, TokenReviews, SubjectAccessReviews, and Leases stall
  -> kubelets, metrics-server, Flux, and CloudNativePG time out
  -> Vault and monitoring remain unready
  -> GitLab, Harbor, Grafana, Fluent Bit, and other monitoring dependents wait
```

The incorrect global ingress override is the primary blocker and is ours.
Big Bang documents `controlPlaneCidr` and
`networkPolicies.ingress.definitions.kubeAPI` as different settings:

- `controlPlaneCidr` is package egress to the Kubernetes API. The local
  `10.77.0.8/29` value is correct for API endpoints `.11`, `.12`, and `.13`.
- `ingress.definitions.kubeAPI` is incoming API-server traffic to webhooks.
  Big Bang intentionally defaults this to the RFC1918 ranges, including both
  the physical `10.77.x.x` nodes and Cilium's `10.233.x.x` node-router
  addresses.

The local profile had replaced that second definition with the first `/29`.
That override has been removed from the local desired state so the documented
Big Bang ingress definition is authoritative again. The live snapshot above
still contains the previous value until Flux receives the corrected revision.

## Blocker ledger

| Component | Classification | What it is doing | Required correction |
| --- | --- | --- | --- |
| Big Bang global NetworkPolicy values plus Cilium | Primary blocker; Atum regression | The narrowed global `kubeAPI` ingress definition excludes Cilium's cross-node router identities. | Remove the Atum ingress-definition override. Retain only `controlPlaneCidr=10.77.0.8/29`; let Big Bang own the documented RFC1918 webhook-ingress definition. |
| Kyverno | Choke point, not a broken package | It is the validating admission webhook reached by nearly every API mutation. Its policy correctly enforces the bad input it received. | No Kyverno workload patch. Restore the upstream Big Bang ingress definition. |
| Istiod | Cilium-specific edge, removed from the clean design | Istiod `1.30.3-bb.0` defaults webhook ports `443` and `15017` to `0.0.0.0/0`. Cilium treats that peer as external `world`, not the observed remote-node identity. | The fresh deployment selects Kubespray's Calico default and retains the Istiod package default; no Istiod NetworkPolicy override remains. |
| Vault | Narrow Big Bang migration edge and current secondary blocker | Big Bang `3.31.1`'s Vault migration combines `controlPlaneCidr` and `vpcCidr`. The unused local `vpcCidr=0.0.0.0/0` makes Vault's named `kubeAPI` egress rule `0.0.0.0/0`, which does not admit the observed in-cluster node identity. | Override only Vault's supported `networkPolicies.egress.definitions.kubeAPI` value to `10.77.0.8/29`. Do not patch the workload or controller. |
| Redis | Independent selected chart mismatch; already corrected | Package `27.0.14-bb.0` enables replica autoscaling while the selected topology is standalone, rendering an HPA for an intentionally absent replica StatefulSet. | Explicitly set replica count to zero and replica autoscaling off through supported values. |
| metrics-server | Downstream indicator | It reaches the kubelets, but node 2 and 3 cannot finish webhook authorization while API admission is stalled. | No new patch. Retain only the documented `--kubelet-insecure-tls` value required by Kubespray's self-signed kubelet serving certificates. |
| Flux controllers and CloudNativePG | Downstream victims | Their leader-election Lease writes pass through the blocked admission path and time out. | No controller patch and no forced reconcile. They should recover through ordinary reconciliation after policy is corrected. |
| OpenSearch and Dashboards | Not a blocker | The official chart/application tuples `3.8.0`/`3.8.0` are running with official mirrored images. | No operator and no OpenSearch source build. |

The repository had selected Cilium in its initial commit without a documented
platform requirement. The clean rebuild instead selects Kubespray's Calico
default. This removes the Cilium resource tuning, rollout behavior,
node-aware CIDR mode, unused Envoy metrics exception, and Istiod peer override.
The only new CNI-adjacent value is Kubespray's documented
`kube_proxy_strict_arp=true` requirement for IPVS plus ARP-mode kube-vip.

## Live evidence

Kyverno's admission Pod is `10.233.65.215:9443`. Cilium shows the node-router
identities from the other control-plane nodes being denied at that exact
endpoint:

```text
xx drop (Policy denied) ... identity 33554436->21404:
10.233.66.199:3098 -> 10.233.65.215:9443 tcp SYN
xx drop (Policy denied) ... identity 33554433->21404:
10.233.64.235:13356 -> 10.233.65.215:9443 tcp SYN
```

Flux is healthy enough to run, but its API writes cannot complete:

```text
"msg":"Failed to update lease",
"lock":"flux-system/kustomize-controller-leader-election",
"error":"Put \"https://10.233.0.1:443/apis/coordination.k8s.io/v1/...
?timeout=15s\": context deadline exceeded"
```

metrics-server shows the downstream kubelet authorization symptom:

```text
"Failed to scrape node" err="request failed, status: \"401 Unauthorized\""
node="atum-node-2"
"Failed to scrape node, timeout to access kubelet"
err="Get \"https://10.77.0.13:10250/metrics/resource\":
context deadline exceeded"
```

Vault's injector shows its separate API egress failure:

```text
failed to determine Admissionregistration API version
Get "https://10.233.0.1:443/apis/admissionregistration.k8s.io/v1/
mutatingwebhookconfigurations": net/http: TLS handshake timeout
```

The dependency fan-out visible in Flux is:

```text
monitoring  False  dependency 'bigbang/vault' is not ready
gitlab      False  dependency 'bigbang/monitoring' is not ready
harbor      False  dependency 'bigbang/monitoring' is not ready
grafana     False  dependency 'bigbang/monitoring' is not ready
fluentbit   False  dependency 'bigbang/monitoring' is not ready
```

OpenSearch is evidence that the official charts are not part of this failure:

```text
opensearch             True  Helm install succeeded ... chart opensearch@3.8.0
opensearch-dashboards  True  Helm install succeeded ... chart opensearch-dashboards@3.8.0
opensearch-cluster-master-0            2/2  Running
opensearch-dashboards-64d6bd767-4t7cr  2/2  Running
```

## Why this produced churn

We initially followed each visible failure—metrics-server, CloudNativePG,
Flux, Istiod, Vault—as if it were package-local. The shared failure boundary
is Kubernetes admission. That led to compensating values around downstream
components before the Cilium drop trace identified the common blocked
endpoint.

The correction is deliberately smaller: restore Big Bang's global documented
defaults, select Kubespray's default Calico CNI, retain one Vault API-egress
value for a demonstrated selected-release migration edge, and make no changes
to downstream victims. A fresh deployment remains the proof that this is
deterministic.

There is also separate updater noise that is not cluster churn.
`atum pull updates` currently rebuilds Kubespray's official full-offline
candidate inventories on each run. The repeated download output is an
inefficiency in compatibility selection, but both consecutive runs selected
the same state and ended successfully:

```text
rendering candidate Helm contracts bigbang=3.31.1 kubernetes=1.35.4
attempt=1 candidates=31
PLAY [Collect container images for offline deployment]
...
rendered exact packaged Helm contract ... completed=31 total=31
verified official image runtime contracts completed=165 total=165
upstream state is current
```

The official full-offline inventory includes payloads for unselected CNIs.
Seeing `kubespray-cilium-*` content mirrored into Harbor therefore does not
mean Cilium is deployed; `kube_network_plugin: calico` is the runtime
selection.
