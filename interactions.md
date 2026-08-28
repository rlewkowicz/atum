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

## Fresh Calico deployment follow-up

The clean Calico deployment proved the original admission diagnosis. Kubespray
completed all three nodes with no failures, every Flux Kustomization became
Ready, and Kyverno, Istiod, CloudNativePG, Vault, OpenSearch, and Dashboards
installed without a Cilium-specific policy override. OpenSearch reached green
cluster health on the official `3.8.0` chart and image.

The remaining wait exposed two local ingress-address handoff defects rather
than another Big Bang package failure:

```text
public-ingressgateway  EXTERNAL-IP 10.77.0.20  endpoint 10.233.66.206 node3
kubevip-public-ingressgateway leader=atum-node-2

VIP from Prometheus:
connect timeout after 4.002106 seconds

Gateway ClusterIP from the same container:
HTTP 404 remote=10.233.25.64 connect=0.000354 total=0.004841
```

The selected kube-vip documentation requires per-Service election for
`externalTrafficPolicy: Local`; that mode limits election to nodes with a
Service endpoint. Both gateway Services now use the official Istio chart's
`upstream.service.externalTrafficPolicy` value. kube-vip already has
`svc_election=true`, so Flux can express the complete supported handoff without
a route, host alias, workload patch, or new controller.

The Atum operator also reported:

```text
KeycloakReady=False ProviderError:
POST https://keycloak.atum.test/.../token:
context deadline exceeded
```

Terraform intentionally maps `keycloak.atum.test` to the passthrough VIP
`10.77.0.21`, while the operator NetworkPolicy admitted only the public VIP
`10.77.0.20`. The updater now projects both exact `/32` endpoints: Keycloak on
passthrough and Vault on public. This remains provider-specific egress for the
narrow identity controller, not generic operator execution authority.

## Fresh Calico deployment: remaining shared boundaries

The next ordinary Flux pass proved that Policy Reporter UI was not failing on
an application-specific SSO value. Its startup request timed out before it
could reach the already healthy Keycloak endpoint:

```text
failed to create openIDConnect provider
Get "https://keycloak.atum.test/auth/realms/master/.well-known/openid-configuration":
context deadline exceeded
```

An earlier run showed CoreDNS resolving Kubernetes service names while some
forwarded names timed out at the Terraform-owned libvirt resolver:

```text
[ERROR] plugin/errors: 2 keycloak.atum.test.atum.local. A:
read udp 10.233.66.192:*->10.77.0.1:53: i/o timeout
```

That isolated symptom led to enabling Kubespray's default NodeLocal DNS cache,
but the next clean deployment disproved the proposed fix. Kubespray correctly
projected NodeLocal DNS into each workload:

```text
search vault.svc.cluster.local svc.cluster.local cluster.local atum.local
nameserver 169.254.25.10
options ndots:5
```

The selected Vault package also correctly rendered bb-common's default-deny
egress and its default DNS exception, but that exception selects only the
central CoreDNS Pods:

```yaml
name: default-egress-allow-kube-dns
egress:
  - ports:
      - {port: 53, protocol: UDP}
      - {port: 53, protocol: TCP}
    to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: kube-system
        podSelector:
          matchLabels:
            k8s-app: kube-dns
```

The selected Kubespray Calico guide documents
`calico_endpoint_to_host_action: "ACCEPT"` for pod traffic to same-node
host-network endpoints. A clean rebuild proved that setting was active but
insufficient: Kubernetes workload egress policy rejected the link-local
destination before Calico's endpoint-to-host fallback could admit it. Both
Istio gateways therefore failed certificate bootstrap:

```text
failed to sign CSR: create certificate: rpc error: code = Unavailable
transport: Error while dialing: dial tcp:
lookup istiod.istio-system.svc on 169.254.25.10:53:
read udp 10.233.66.201:*->169.254.25.10:53: i/o timeout
```

An A/B diagnostic added only `169.254.25.10/32` on TCP/UDP 53 to the public
gateway's rendered DNS NetworkPolicy. That gateway immediately connected to
Istiod, generated its workload certificate, and became Ready; the untouched
passthrough gateway remained unready. This proves the policy/destination
mismatch without attributing it to either gateway package or Calico.

Big Bang documents `networkPolicies.additionalPolicies`, but only at each
package boundary. Repeating a NodeLocal exception across every package, or
installing a Calico-specific global policy, would replace one supported default
with broad Atum-owned policy. The inventory instead disables optional
NodeLocal DNS and retains Kubespray-owned CoreDNS, matching bb-common's native
`k8s-app: kube-dns` rule.

The following clean startup then invalidated the earlier short, 200-query
CoreDNS probe. Atum had also reduced Kubespray's documented two-replica
CoreDNS floor to one. Normal `ndots:5` search expansion and simultaneous
package startup saturated that singleton. Its metrics showed:

```text
coredns_dns_requests_total:       495348
coredns_dns_responses_total{rcode="SERVFAIL"}: 136578
coredns_forward_max_concurrent_rejects_total:    8741
coredns_proxy_conn_cache_misses_total{proto="udp"}: 411654
go_goroutines: 938
```

CoreDNS received workload requests, but its one-use UDP forwards to the
Terraform-owned resolver repeatedly expired:

```text
[ERROR] plugin/errors: 2 keycloak.atum.test.atum.local. A:
read udp 10.233.66.194:*->10.77.0.1:53: i/o timeout
```

This produced the same downstream symptom in Policy Reporter and the narrow
Atum operator even though the passthrough gateway itself returned HTTP 200
when the hostname was pinned to its ClusterIP. Kubespray documents
`dns_upstream_forward_extra_opts` as the extension point for the CoreDNS
forward block, and CoreDNS specifies that `force_tcp` overrides the built-in
`prefer_udp` behavior. The inventory now uses that option and removes both
singleton replica settings, restoring Kubespray's default two-replica floor.

The Calico endpoint-to-host override is removed with NodeLocal DNS. Terraform
still owns dnsmasq, Kubespray still owns cluster DNS and the CNI, and Big Bang
retains its unmodified default-deny policies and strict mesh settings.

Once TCP forwarding removed the DNS timeout, Policy Reporter exposed the next
independent boundary:

```text
failed to create openIDConnect provider
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

The exact Keycloak discovery URL returned HTTP 200 from the same sidecar in
about 12 milliseconds, proving service and mesh reachability. Big Bang
`3.31.1` passes that private-CA URL into Kyverno Reporter but does not create
its documented SSO CA Secret in the package namespace. Policy Reporter
`3.9.1` already exposes `ui.openIDConnect.certificate`, `ui.extraVolumes`, and
`extraManifests`. The generated identity values therefore use those native
interfaces to request one cert-manager Certificate, mount only its `ca.crt`,
and keep OIDC verification enabled. No generic operator behavior or
post-render patch is involved.

GitLab registry exposed one independent, documented Garage consumer edge:

```text
S3: retrying after error
api error ServiceUnavailable: Service Unavailable
```

Garage itself was healthy and the `gitlab-registry` bucket and key existed.
The selected Garage values explicitly say to add one
`bb-common.networkPolicies.ingress.to.garage:3900.from.k8s` entry per S3
consumer, but its rendered policy admitted only the ingress gateway. GitLab
already had matching egress to the Garage namespace. The values now add the
documented `gitlab/gitlab` consumer shorthand; no workload or Service is
patched.

The Atum operator reached Keycloak after the passthrough policy fix and then
reported:

```text
administrator: /users "atum" exists without
platform.atum.dev/owner=atum-system/atum
```

The created user's fields exactly matched the operator payload, but a direct
read showed `attributes: null`. Keycloak's default declarative user profile
ignores undeclared attributes, so the ownership marker in the create request
was discarded before the next reconcile. Because this platform is greenfield,
the canonical marker is now the valid profile attribute name `atum_owner`.
The operator declares that one admin-only managed attribute first, requests
full user representations, and continues to reject an existing unmarked user.
This is narrow Keycloak provider state; it does not adopt arbitrary users or
expand the operator into platform lifecycle management.
