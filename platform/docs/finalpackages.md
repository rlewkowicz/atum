# Final Package Set

## Overview

This is the minimal enterprise cluster package set using OSI-approved open-source tooling.

The local profile exposes the Big Bang-managed Headlamp release at
`https://headlamp.atum.test`. After convergence, obtain an ephemeral login
token directly from Kubernetes when needed:

```sh
kubectl -n headlamp create token headlamp-headlamp --duration=24h
```

Atum does not generate, store, or print the resulting bearer token.

The URL is printed only after the local resolver, public gateway VIP,
certificate SAN and validity, and installed CA fingerprint are exact. Paste
the freshly minted token into Headlamp's token login and allow it to expire or
revoke it when finished. Inspect or remove the workstation lifecycle with
`atum infra access status` and `atum infra access uninstall`.

The local profile alone deploys kube-vip, its `10.77.0.22-10.77.0.39`
allocator, the `atum.test` issuers, and the public and passthrough certificates.
Cloud profiles retain provider-native unannotated `LoadBalancer` Services and
exclude all workstation DNS and CA integration.

## License Boundary

Included packages use OSI-approved open-source licenses such as Apache-2.0, MIT, MPL-2.0, and AGPLv3.

## Platform Foundation

| Function | Package | License | Source |
| --- | --- | --- | --- |
| GitOps prerequisite | FluxCD | Apache-2.0 | [fluxcd/flux2](https://github.com/fluxcd/flux2) |
| Certificate automation | cert-manager | Apache-2.0 | [cert-manager/cert-manager](https://github.com/cert-manager/cert-manager) |
| Prep local storage | Rancher Local Path Provisioner | Apache-2.0 | [rancher/local-path-provisioner](https://github.com/rancher/local-path-provisioner) |
| Service mesh CRDs | Istio CRDs | Apache-2.0 | [istio/istio](https://github.com/istio/istio) |
| Service mesh control plane | Istiod | Apache-2.0 | [istio/istio](https://github.com/istio/istio) |
| Ingress gateway | Istio Gateway | Apache-2.0 | [istio/istio](https://github.com/istio/istio) |
| Service mesh console | Kiali | Apache-2.0 | [kiali/kiali](https://github.com/kiali/kiali) |
| Kubernetes console | Headlamp | Apache-2.0 | [headlamp-k8s/headlamp](https://github.com/headlamp-k8s/headlamp) |

## Identity And Access

| Function | Package | License | Source |
| --- | --- | --- | --- |
| Identity provider | Keycloak | Apache-2.0 | [keycloak/keycloak](https://github.com/keycloak/keycloak) |
| Istio authorization service | Authservice | Apache-2.0 | [istio-ecosystem/authservice](https://github.com/istio-ecosystem/authservice) |

## Policy And Security

| Function | Package | License | Source |
| --- | --- | --- | --- |
| Admission policy engine | Kyverno | Apache-2.0 | [kyverno/kyverno](https://github.com/kyverno/kyverno) |
| Policy bundle | Kyverno Policies | Apache-2.0 | [kyverno/policies](https://github.com/kyverno/policies) |
| Policy reporting | Kyverno Reporter | MIT | [kyverno/policy-reporter](https://github.com/kyverno/policy-reporter) |
| Secrets management | OpenBao | MPL-2.0 | [openbao/openbao](https://github.com/openbao/openbao) |

## Observability

| Function | Package | License | Source |
| --- | --- | --- | --- |
| Monitoring CRDs | Prometheus Operator CRDs | Apache-2.0 | [prometheus-operator/prometheus-operator](https://github.com/prometheus-operator/prometheus-operator) |
| Metrics collection and alerting | Monitoring | Apache-2.0 | [prometheus-operator/kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) |
| Dashboards | Grafana | AGPLv3 | [grafana/grafana](https://github.com/grafana/grafana) |
| Distributed tracing | Tempo | AGPLv3 | [grafana/tempo](https://github.com/grafana/tempo) |
| Log forwarding | Fluent Bit | Apache-2.0 | [fluent/fluent-bit](https://github.com/fluent/fluent-bit) |
| Search and log storage | OpenSearch | Apache-2.0 | [opensearch-project/OpenSearch](https://github.com/opensearch-project/OpenSearch) |
| Search dashboard | OpenSearch Dashboards | Apache-2.0 | [opensearch-project/OpenSearch-Dashboards](https://github.com/opensearch-project/OpenSearch-Dashboards) |
| Search operator | OpenSearch Kubernetes Operator | Apache-2.0 | [opensearch-project/opensearch-k8s-operator](https://github.com/opensearch-project/opensearch-k8s-operator) |

## Development And Delivery

| Function | Package | License | Source |
| --- | --- | --- | --- |
| Bastion seed Git service | Forgejo | GPL-3.0-or-later | [forgejo/forgejo](https://codeberg.org/forgejo/forgejo) |
| Source control and CI | GitLab Community Edition | MIT | [gitlab-org/gitlab](https://gitlab.com/gitlab-org/gitlab) |
| In-cluster OCI image registry | Harbor | Apache-2.0 | [goharbor/harbor](https://github.com/goharbor/harbor) |

## Recovery

| Function | Package | License | Source |
| --- | --- | --- | --- |
| Backup and restore | Velero | Apache-2.0 | [vmware-tanzu/velero](https://github.com/vmware-tanzu/velero) |
