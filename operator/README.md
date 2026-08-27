# Atum identity operator

The Atum operator reconciles one
`platform.atum.dev/v1alpha1 PlatformIdentityConfiguration` named
`atum-system/atum`. Flux owns the CRD, controller deployment, RBAC, Secrets,
and desired custom resource. The controller owns only the provider API objects
listed below and reports their state through `KeycloakReady`, `VaultReady`, and
`Ready` conditions for the current `metadata.generation`.

Generated admission requires the complete `spec` and singleton name `atum`.
CRD CEL does not expose `metadata.namespace`; namespace custody is instead one
native boundary formed by Flux placement, the `atum-system` manager cache,
Role and RoleBinding, the controller request guard, and the CLI's exact
`atum-system/atum` lookup.

## Admission boundary

A manual upstream step is eligible only when it is required for Atum's
steady-state baseline, creates provider/service API state, cannot be expressed
by the selected chart or an upstream controller, fits this closed typed API,
has idempotent ownership/deletion/retry/Secret semantics, and exposes
provider-native readiness. The operator never accepts arbitrary endpoints,
Secret names, scripts, commands, manifests, generic maps, plugins, or
Kubernetes work.

The controller owns these Keycloak classes:

- one administrator user, its group membership, and its declared realm role;
- one groups client scope and its fixed groups mapper;
- the declared public-PKCE or confidential OIDC clients;
- audience mappers explicitly selected by a typed client field.

It owns these Vault classes:

- one OIDC auth method;
- one platform-administration policy;
- one OIDC role;
- one external identity group and its alias.

Keycloak is fixed at `https://keycloak.<spec.domain>/auth`, Vault at
`https://vault.<spec.domain>`, and the realm is `master`. Credentials are read
only from `atum-system/atum-provider-credentials`,
`atum-system/atum-provider-ca`, and `vault/vault-token`. RBAC names those
Secrets explicitly.

An Atum ownership marker prevents adoption of colliding provider objects.
Deletion prunes marked objects plus the one exact declared Vault role
`atum-admin`. Other Vault roles are never reconciled or deleted. A foreign
role beneath the marked auth mount blocks mount deletion with a repairable
conflict, retaining the finalizer until an administrator removes that role.
The finalizer is removed when cleanup is complete or the credential source has
already been pruned. Provider conflicts are terminal during normal
reconciliation; transient failures use bounded backoff.

## Selected manual-step evidence

| Selected source | Decision |
| --- | --- |
| Headlamp package `bdee331b4cba0ddece5b9b2e2b5b72a32f6e5ebd`, chart/application `0.44.0` | The package guide documents a `headlampId` user attribute mapper, but the selected chart passes only OIDC client, issuer, scopes, PKCE, and token-choice inputs. Headlamp `v0.44.0` verifies and forwards the selected ID/access token, and its user projection reads `preferred_username`, `email`, and `groups`; it contains no `headlampId` consumer. Atum therefore adds no mapper or administrator attribute. |
| Monitoring package `f6c4fad5f5a89f2b33c5fdadc557f7f7a8d3117a` | The guide's named `Grafana` scope is an example bundle of standard profile, email, username, role, and groups mappers. The selected Grafana values request `openid,profile,email,groups` and authorize from `groups`; Prometheus and Alertmanager use Authservice clients with the same standard scopes. The existing canonical scopes and groups mapper cover the rendered consumers. |
| Vault package `51721eb137561b518f22cba0e2e28a7610c03043` | The package explicitly leaves Keycloak client/group mapping and Vault OIDC auth, policy, role, and group alias configuration manual. Those provider objects are the positive admission case and are represented directly by the typed spec. Initialization, unseal, root-token custody, backup, and rotation remain excluded operations. |

## Generation

API and RBAC markers are authoritative. Generated artifacts consumed by Flux
are deterministic projections:

```sh
make generate
make manifests
make project-operator
make verify-operator
```

`generate` owns `zz_generated.deepcopy.go`. `manifests` owns the CRD under
`config/crd/bases` and the namespace Role under `config/rbac`.
`project-operator` copies those exact bytes into
`platform/apps/atum-operator`; the remaining hand-authored RBAC contains only
the namespace RoleBindings and the fixed Vault-token Role.

Excluded responsibilities include infrastructure, Kubernetes authentication
or RBAC, Helm releases, workloads, certificates, Secret projection, local-host
state, Vault initialization/unseal, backup/restore, rotation, upgrades, and
break-glass procedures.
