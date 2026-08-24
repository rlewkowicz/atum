# Final Package Set

## Overview

This is the minimal enterprise cluster package set using OSI-approved open-source tooling.

The local profile uses the Keycloak master realm as its single human-identity
authority. The permanent local-development administrator is `atum` / `atum`;
it belongs to `atum-admins`, receives Keycloak server administration, and is
mapped to the highest supported administrator role in each integrated
application. The derived bootstrap administrator is retired after this
permanent login is verified.

After convergence, the managed TUI shows one final Access panel only when the
resolver, public and passthrough VIPs, certificate SANs and validity, installed
CA fingerprint, identity reconciliation, and Kubernetes OIDC receipt are all
exact. The panel contains workstation paths and fingerprints, the Keycloak
issuer and administrator console, the local credentials, categorized browser
URLs, and token-backed protocol endpoints. Inspect or remove workstation state
with `atum infra access status` and `atum infra access uninstall`.

Headlamp uses native Keycloak OIDC. Kubernetes maps `atum-admins` to
`oidc:atum-admins` and binds that group to `cluster-admin`; no Headlamp
service-account token is created or displayed. Kiali, Grafana, GitLab, Policy
Reporter, Harbor, and OpenBao use native or reconciled OIDC. Prometheus,
Alertmanager, and OpenSearch Dashboards remain behind Big Bang Authservice.
GitLab KAS and the registry remain application-token protocol endpoints rather
than browser OIDC routes.

### Local Identity Integration Matrix

| Browser endpoint | Identity integration | Administrator result |
| --- | --- | --- |
| Keycloak | Master realm | Keycloak server administrator |
| Headlamp | Native PKCE | Kubernetes `cluster-admin` through `oidc:atum-admins` |
| Kiali | Native OpenID | Authenticated cluster administrator |
| Grafana | Generic OAuth | Grafana `Admin` |
| GitLab | OmniAuth | GitLab administrator through `atum-admins` |
| Policy Reporter | Native OIDC | Authenticated UI administrator |
| Harbor | Native OIDC | Harbor administrator through `atum-admins` |
| OpenBao | Reconciled OIDC | Broad local administrator policy |
| Prometheus | Big Bang Authservice | Authenticated access |
| Alertmanager | Big Bang Authservice | Authenticated access |
| OpenSearch Dashboards | Big Bang Authservice | Authenticated access |

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
