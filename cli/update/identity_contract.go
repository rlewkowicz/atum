package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"atum/cli/config"
	"atum/cli/identity"
	platformv1alpha1 "atum/operator/api/v1alpha1"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

const identityTemplateRoot = "platform/templates/identity"

const renderOnlyIdentityCredential = "atum-render-only-credential-0000000000000000"

const policyReporterCACertificatePath = "/var/run/atum-sso/ca.crt"

const policyReporterCACertificateManifest = `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: atum-sso-ca
  namespace: kyverno-reporter
spec:
  commonName: sso-ca.kyverno-reporter
  dnsNames:
    - sso-ca.kyverno-reporter
  duration: 8760h
  renewBefore: 720h
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: atum-test-ca
  secretName: atum-sso-ca
`

var atumRenderPlaceholderPattern = regexp.MustCompile(`\$\{(ATUM_[A-Z0-9_]+)\}`)

type identityRenderContext struct {
	Values                 string
	OperatorConfiguration  string
	PublicIngressCIDR      string
	PassthroughIngressCIDR string
	Namespace              string
	Cluster                string
}

type identityOutput struct {
	template string
	path     string
	context  func(identityRenderContext) any
}

func loadCandidateIdentity(tree *candidateTree, desired config.Document) (*identity.Contract, error) {
	valuesPath, configured := desired.Platform.Values.Profiles["local"]
	if !configured {
		return nil, nil
	}
	relative := filepath.Join(filepath.Dir(filepath.Dir(valuesPath)), "identity", "contract.yaml")
	data, err := tree.CandidateData(relative)
	if err != nil {
		return nil, err
	}
	return identity.Parse(data, relative)
}

func identityValues(
	contract *identity.Contract,
	localAccess *config.LocalAccess,
) (map[string]any, error) {
	if contract == nil {
		return map[string]any{}, nil
	}
	if localAccess == nil {
		return nil, errors.New("local access is required for identity values")
	}
	ssoEndpointCIDR, err := ipv4HostCIDR(
		"local passthrough ingress VIP",
		localAccess.PassthroughIngressVIP,
	)
	if err != nil {
		return nil, err
	}
	client := func(application identity.Application) (identity.Client, error) {
		value, found := contract.ClientForApplication(application)
		if !found {
			return identity.Client{}, fmt.Errorf(
				"identity contract has no %s application projection", application)
		}
		return value, nil
	}
	secret := func(value identity.Client) string {
		return "${" + identitySecretKey(value.ID) + "}"
	}
	headlamp, err := client(identity.Headlamp)
	if err != nil {
		return nil, err
	}
	kiali, err := client(identity.Kiali)
	if err != nil {
		return nil, err
	}
	grafana, err := client(identity.Grafana)
	if err != nil {
		return nil, err
	}
	gitlab, err := client(identity.GitLab)
	if err != nil {
		return nil, err
	}
	reporter, err := client(identity.PolicyReporter)
	if err != nil {
		return nil, err
	}
	harbor, err := client(identity.Harbor)
	if err != nil {
		return nil, err
	}
	prometheus, err := client(identity.Prometheus)
	if err != nil {
		return nil, err
	}
	alertmanager, err := client(identity.Alertmanager)
	if err != nil {
		return nil, err
	}
	opensearch, err := client(identity.OpenSearch)
	if err != nil {
		return nil, err
	}
	admin := contract.Administrator()
	scopeList := contract.Scopes()
	scopes := strings.Join(scopeList, " ")
	keycloakHost := strings.TrimSuffix(
		strings.TrimPrefix(contract.Issuer(), "https://"), "/auth/realms/master")
	keycloakServiceEntries := []any{map[string]any{
		"name": "keycloak",
		"spec": map[string]any{
			"hosts":      []any{keycloakHost},
			"location":   "MESH_EXTERNAL",
			"resolution": "DNS",
			"ports": []any{map[string]any{
				"number": 443, "name": "tls-keycloak", "protocol": "TLS",
			}},
		},
	}}
	harborSettings, err := json.Marshal(map[string]any{
		"auth_mode":                 "oidc_auth",
		"oidc_name":                 "Atum",
		"oidc_endpoint":             contract.Issuer(),
		"oidc_client_id":            harbor.ID,
		"oidc_client_secret":        secret(harbor),
		"oidc_scope":                scopes,
		"oidc_verify_cert":          true,
		"oidc_auto_onboard":         true,
		"oidc_user_claim":           "preferred_username",
		"oidc_groups_claim":         contract.GroupClaim(),
		"oidc_admin_group":          admin.Group,
		"oidc_group_filter":         "",
		"oidc_extra_redirect_parms": map[string]string{},
	})
	if err != nil {
		return nil, fmt.Errorf("encode Harbor identity settings: %w", err)
	}
	authChains := make(map[string]any, 4)
	authChains["local"] = nil
	for _, projected := range contract.Clients() {
		if projected.Integration != identity.Authservice {
			continue
		}
		authChains[string(projected.Application)] = map[string]any{
			"callback_uri":  projected.Callbacks[0],
			"client_id":     projected.ID,
			"client_secret": secret(projected),
			"match": map[string]any{
				"header": ":authority",
				"prefix": projected.Host,
			},
		}
	}
	return map[string]any{
		"sso": map[string]any{
			"name": "Atum",
			"url":  contract.Issuer(),
			"oidc": map[string]any{
				"discoveryUrl":  contract.Issuer() + "/.well-known/openid-configuration",
				"authorization": contract.Issuer() + "/protocol/openid-connect/auth",
				"endSession":    contract.Issuer() + "/protocol/openid-connect/logout",
				"jwksUri":       contract.Issuer() + "/protocol/openid-connect/certs",
				"token":         contract.Issuer() + "/protocol/openid-connect/token",
				"userinfo":      contract.Issuer() + "/protocol/openid-connect/userinfo",
				"claims": map[string]any{
					"email": "email", "name": "name",
					"username": "preferred_username", "groups": contract.GroupClaim(),
				},
			},
		},
		"networkPolicies": map[string]any{
			"egress": map[string]any{"definitions": map[string]any{
				"sso": map[string]any{
					"to": []any{map[string]any{
						"ipBlock": map[string]any{"cidr": ssoEndpointCIDR},
					}},
					"ports": []any{map[string]any{"port": 443, "protocol": "TCP"}},
				},
			}},
		},
		"kiali": map[string]any{
			"sso": map[string]any{
				"enabled": true, "client_id": kiali.ID, "client_secret": secret(kiali),
			},
		},
		"grafana": map[string]any{"sso": map[string]any{
			"enabled": true,
			"grafana": map[string]any{
				"client_id": grafana.ID, "client_secret": secret(grafana),
				"scopes": strings.Join(scopeList, ","), "allow_sign_up": true,
				"role_attribute_path": fmt.Sprintf(
					"contains(groups[*], '%s') && '%s' || 'Viewer'",
					admin.Group, grafana.AdministratorMapping),
			},
		}},
		"monitoring": map[string]any{"sso": map[string]any{
			"enabled": true,
			"prometheus": map[string]any{
				"client_id": prometheus.ID, "client_secret": secret(prometheus),
			},
			"alertmanager": map[string]any{
				"client_id": alertmanager.ID, "client_secret": secret(alertmanager),
			},
		}},
		"kyvernoReporter": map[string]any{
			"sso": map[string]any{
				"enabled": true, "client_id": reporter.ID, "client_secret": secret(reporter),
			},
			"values": map[string]any{
				"routes": map[string]any{"inbound": map[string]any{
					"policy-reporter-ui": map[string]any{"hosts": []any{reporter.Host}},
				}},
				"upstream": map[string]any{
					"extraManifests": []any{policyReporterCACertificateManifest},
					"ui": map[string]any{
						"extraVolumes": map[string]any{
							"volumeMounts": []any{map[string]any{
								"name":      "atum-sso-ca",
								"mountPath": "/var/run/atum-sso",
								"readOnly":  true,
							}},
							"volumes": []any{map[string]any{
								"name": "atum-sso-ca",
								"secret": map[string]any{
									"secretName": "atum-sso-ca",
									"items": []any{map[string]any{
										"key": "ca.crt", "path": "ca.crt",
									}},
								},
							}},
						},
						"openIDConnect": map[string]any{
							"enabled": true, "discoveryUrl": contract.Issuer() + "/.well-known/openid-configuration",
							"callbackUrl": reporter.Callbacks[0], "clientId": reporter.ID,
							"clientSecret": secret(reporter),
							"certificate":  policyReporterCACertificatePath,
						},
					},
				},
			},
		},
		"addons": map[string]any{
			"authservice": map[string]any{
				"chains": authChains,
			},
			"gitlab": map[string]any{"sso": map[string]any{
				"enabled": true, "client_id": gitlab.ID, "client_secret": secret(gitlab),
				"scopes": scopeList,
				"groups": map[string]any{
					"groupsAttribute": contract.GroupClaim(),
					"adminGroups":     []any{admin.Group},
					"requiredGroups":  []any{},
				},
			}},
			"harbor": map[string]any{"values": map[string]any{"upstream": map[string]any{
				"caBundleSecretName": "atum-sso-ca",
				"core":               map[string]any{"configureUserSettings": string(harborSettings)},
			}}},
			"headlamp": map[string]any{
				"sso": map[string]any{
					"enabled": true, "client_id": headlamp.ID, "client_secret": "",
				},
				"values": map[string]any{
					"bigbang": map[string]any{"rbac": map[string]any{
						"enabled":      true,
						"clusterRoles": []any{},
						"clusterRoleBindings": []any{map[string]any{
							"name": headlamp.ID + "-admin", "roleRef": "cluster-admin",
							"subjects": []any{map[string]any{
								"kind": "Group", "name": "oidc:" + admin.Group,
								"apiGroup": "rbac.authorization.k8s.io",
							}},
						}},
					}},
					"upstream": map[string]any{
						"clusterRoleBinding": map[string]any{"create": false},
						"config": map[string]any{"oidc": map[string]any{
							"clientID": headlamp.ID, "issuerURL": contract.Issuer(),
							"scopes": strings.Join(scopeList, ","), "usePKCE": true,
							"secret": map[string]any{"create": false},
						}},
					},
				},
			},
			"keycloak": map[string]any{"values": map[string]any{"upstream": map[string]any{
				"secrets": map[string]any{"env": map[string]any{"stringData": map[string]any{
					"KEYCLOAK_ADMIN":          "atum-bootstrap",
					"KEYCLOAK_ADMIN_PASSWORD": "${ATUM_IDENTITY_BOOTSTRAP_PASSWORD}",
				}}},
			}}},
			"vault": map[string]any{"values": map[string]any{
				"istio": map[string]any{"serviceEntries": map[string]any{
					"custom": keycloakServiceEntries,
				}},
				"networkPolicies": map[string]any{"egress": map[string]any{"from": map[string]any{
					"vault": map[string]any{"to": map[string]any{"definition": map[string]any{
						"sso": true,
					}}},
				}}},
				"upstream": map[string]any{"server": map[string]any{
					"extraEnvironmentVars": map[string]any{"VAULT_CACERT": "/var/run/atum-sso/ca.crt"},
					"volumes": []any{map[string]any{
						"name": "atum-sso-ca", "secret": map[string]any{"secretName": "atum-sso-ca"},
					}},
					"volumeMounts": []any{map[string]any{
						"name": "atum-sso-ca", "mountPath": "/var/run/atum-sso",
						"readOnly": true,
					}},
				},
				}}},
		},
		"packages": map[string]any{
			"opensearch": map[string]any{
				"sso": map[string]any{"enabled": true},
				"istio": map[string]any{
					"hosts": []any{map[string]any{
						"names": []any{strings.TrimSuffix(
							opensearch.Host, "."+contract.Domain())},
						"domains":  []any{contract.Domain()},
						"gateways": []any{"istio-gateway/public-ingressgateway"},
						"selectors": []any{map[string]any{"matchLabels": map[string]any{
							"protect": "keycloak",
						}}},
						"destination": map[string]any{
							"protocol": "http", "service": "opensearch-dashboards", "port": 5601,
						},
					}},
					"hardened": map[string]any{
						"matchLabels": map[string]any{"protect": "keycloak"},
					},
				},
			},
			"opensearch-dashboards": map[string]any{"values": map[string]any{
				"labels": map[string]any{"protect": "keycloak"},
			}},
		},
	}, nil
}

func mergeIdentityValues(base, identityValues map[string]any) (map[string]any, error) {
	if len(identityValues) == 0 {
		return cloneMap(base), nil
	}
	result := cloneMap(base)
	mergeMaps(result, identityValues)
	return result, nil
}

// renderFluxSubstitutedValues models the local profile Kustomization's
// postBuild substitutions for updater-only Helm inspection. Persisted values
// retain their Flux placeholders; non-secret sentinels let the exact selected
// charts validate and expose every conditionally enabled runtime image.
func renderFluxSubstitutedValues(
	desired config.Document,
	contract *identity.Contract,
	values map[string]any,
) (map[string]any, error) {
	target, found := desired.ActiveTarget()
	if !found {
		return nil, errors.New("active platform target is unavailable")
	}
	if target.LocalAccess == nil {
		return nil, fmt.Errorf(
			"platform profile %s has no local Flux substitutions",
			target.PlatformProfile,
		)
	}
	replacements := map[string]string{
		"ATUM_PLATFORM_DOMAIN":             target.LocalAccess.Domain,
		"ATUM_IDENTITY_BOOTSTRAP_PASSWORD": renderOnlyIdentityCredential,
	}
	if contract != nil {
		for _, client := range contract.Clients() {
			replacements[identitySecretKey(client.ID)] = renderOnlyIdentityCredential
		}
	}
	rendered := cloneMap(values)
	if err := substituteRenderPlaceholders(rendered, replacements, nil); err != nil {
		return nil, err
	}
	// The Big Bang HelmRelease receives the controller-created atum-sso-ca
	// Secret through an optional valuesFrom targetPath. That Secret does not
	// exist in the static updater tree, so model only its non-empty runtime
	// shape in memory to expose every CA-gated child-chart resource.
	if err := setNestedValue(
		rendered,
		"sso.certificateAuthority.cert",
		"-----BEGIN CERTIFICATE-----\nYXR1bS1yZW5kZXItb25seQ==\n-----END CERTIFICATE-----",
	); err != nil {
		return nil, fmt.Errorf(
			"model Flux SSO certificate authority valuesFrom: %w",
			err,
		)
	}
	return rendered, nil
}

func substituteRenderPlaceholders(
	value any,
	replacements map[string]string,
	path []string,
) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := append(path, key)
			if text, ok := child.(string); ok {
				rendered, missing := substituteRenderText(text, replacements)
				typed[key] = rendered
				if missing != "" {
					return fmt.Errorf(
						"Flux render value %s uses unavailable substitution %s",
						strings.Join(childPath, "."),
						missing,
					)
				}
				continue
			}
			if err := substituteRenderPlaceholders(
				child,
				replacements,
				childPath,
			); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			childPath := append(path, fmt.Sprintf("[%d]", index))
			if text, ok := child.(string); ok {
				rendered, missing := substituteRenderText(text, replacements)
				typed[index] = rendered
				if missing != "" {
					return fmt.Errorf(
						"Flux render value %s uses unavailable substitution %s",
						strings.Join(childPath, "."),
						missing,
					)
				}
				continue
			}
			if err := substituteRenderPlaceholders(
				child,
				replacements,
				childPath,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func substituteRenderText(
	value string,
	replacements map[string]string,
) (string, string) {
	var missing string
	rendered := atumRenderPlaceholderPattern.ReplaceAllStringFunc(
		value,
		func(placeholder string) string {
			name := placeholder[2 : len(placeholder)-1]
			replacement, found := replacements[name]
			if !found {
				if missing == "" {
					missing = name
				}
				return placeholder
			}
			return replacement
		},
	)
	return rendered, missing
}

func configurePlatformValuesFrom(release map[string]any) error {
	valuesFrom := make([]any, len(platformValuesSources))
	for index, source := range platformValuesSources {
		valuesFrom[index] = source.fluxValue()
	}
	if err := setNestedValue(release, "spec.valuesFrom", valuesFrom); err != nil {
		return fmt.Errorf("configure Big Bang values precedence: %w", err)
	}
	return nil
}

func firstNestedCollision(left, right map[string]any, prefix []string) string {
	for key, rightValue := range right {
		leftValue, exists := left[key]
		if !exists {
			continue
		}
		path := append(prefix, key)
		leftMap, leftOK := leftValue.(map[string]any)
		rightMap, rightOK := rightValue.(map[string]any)
		if leftOK && rightOK {
			if nested := firstNestedCollision(leftMap, rightMap, path); nested != "" {
				return nested
			}
			continue
		}
		return strings.Join(path, ".")
	}
	return ""
}

func mergeMaps(destination, source map[string]any) {
	for key, value := range source {
		sourceMap, sourceIsMap := value.(map[string]any)
		destinationMap, destinationIsMap := destination[key].(map[string]any)
		if sourceIsMap && destinationIsMap {
			mergeMaps(destinationMap, sourceMap)
			continue
		}
		destination[key] = cloneValue(value)
	}
}

func renderIdentityManifests(
	tree *candidateTree,
	desired config.Document,
	contract *identity.Contract,
	identityValues map[string]any,
) error {
	target, found := desired.ActiveTarget()
	if !found {
		return errors.New("active platform target is unavailable")
	}
	context, err := newIdentityRenderContext(
		contract,
		identityValues,
		target.LocalAccess,
	)
	if err != nil {
		return err
	}
	context.Cluster = desired.Project.Cluster
	clusterRoot := filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster)
	for _, name := range [...]string{"prep.yaml"} {
		relative := filepath.Join(clusterRoot, name)
		current, err := tree.YAML(relative)
		if err != nil {
			return fmt.Errorf("read Flux consumer %s: %w", relative, err)
		}
		candidate := cloneMap(current)
		spec, ok := candidate["spec"].(map[string]any)
		if !ok {
			return fmt.Errorf("Flux consumer %s has no spec", relative)
		}
		spec["force"] = false
		delete(spec, "healthChecks")
		delete(spec, "healthCheckExprs")
		if err := setCandidateYAML(tree, relative, current, candidate); err != nil {
			return fmt.Errorf("render explicit Flux defaults in %s: %w", relative, err)
		}
	}
	bigBangRelative := filepath.Join(clusterRoot, "bigbang.yaml")
	currentBigBang, err := tree.YAML(bigBangRelative)
	if err != nil {
		return fmt.Errorf("read Flux consumer %s: %w", bigBangRelative, err)
	}
	candidateBigBang := cloneMap(currentBigBang)
	if err := config.NormalizeBigBangReadinessKustomization(
		candidateBigBang,
	); err != nil {
		return fmt.Errorf(
			"normalize Flux consumer %s: %w",
			bigBangRelative,
			err,
		)
	}
	if err := setCandidateYAML(
		tree, bigBangRelative, currentBigBang, candidateBigBang,
	); err != nil {
		return fmt.Errorf(
			"render Big Bang Flux readiness gate in %s: %w",
			bigBangRelative,
			err,
		)
	}
	outputs := []identityOutput{
		{"cluster-root.yaml.tmpl", filepath.Join(clusterRoot, "kustomization.yaml"), nil},
		{"cluster-profile-prep.yaml.tmpl", filepath.Join(clusterRoot, "platform-profile-prep.yaml"), nil},
		{"cluster-profile-access.yaml.tmpl", filepath.Join(clusterRoot, "platform-profile-access.yaml"), nil},
		{"cluster-platform-certificates.yaml.tmpl", filepath.Join(clusterRoot, "platform-certificates.yaml"), nil},
		{"cluster-atum-operator.yaml.tmpl", filepath.Join(clusterRoot, "atum-operator.yaml"), nil},
		{"local-prep-kustomization.yaml.tmpl", "platform/profiles/local/prep/kustomization.yaml", nil},
		{"local-prep-certificates-kustomization.yaml.tmpl", "platform/profiles/local/prep/certificates/kustomization.yaml", nil},
		{"identity-certificate.yaml.tmpl", "platform/profiles/local/prep/certificates/identity-certificate.yaml", nil},
		{"identity-values.yaml.tmpl", "platform/profiles/local/prep/identity-values.yaml", nil},
		{"local-access-kustomization.yaml.tmpl", "platform/profiles/local/access/kustomization.yaml", nil},
		{"operator-configuration.yaml.tmpl", "platform/apps/atum-operator/configuration.yaml", nil},
		{"operator-network-policy.yaml.tmpl", "platform/apps/atum-operator/network-policy.yaml", nil},
	}
	for _, namespace := range []string{"harbor", "keycloak", "vault"} {
		namespace := namespace
		outputs = append(outputs, identityOutput{
			template: "local-access-ca.yaml.tmpl",
			path:     filepath.Join("platform/profiles/local/access/certificates", namespace+"-sso-ca.yaml"),
			context: func(base identityRenderContext) any {
				base.Namespace = namespace
				return base
			},
		})
	}
	for _, output := range outputs {
		templatePath := filepath.Join(identityTemplateRoot, output.template)
		source, err := tree.CandidateData(templatePath)
		if err != nil {
			return fmt.Errorf("read identity template %s: %w", templatePath, err)
		}
		parsed, err := template.New(output.template).Funcs(template.FuncMap{
			"indent": indentTemplate,
		}).Option("missingkey=error").Parse(string(source))
		if err != nil {
			return fmt.Errorf("parse identity template %s: %w", templatePath, err)
		}
		value := any(context)
		if output.context != nil {
			value = output.context(context)
		}
		var rendered bytes.Buffer
		if err := parsed.Execute(&rendered, value); err != nil {
			return fmt.Errorf("render identity template %s: %w", templatePath, err)
		}
		data := rendered.Bytes()
		if len(data) == 0 || data[len(data)-1] != '\n' {
			data = append(data, '\n')
		}
		if err := validateIdentityYAML(output.path, data); err != nil {
			return err
		}
		if err := tree.Set(filepath.ToSlash(output.path), data); err != nil {
			return err
		}
	}
	for _, relative := range []string{
		"platform/profiles/local/identity/kustomization.yaml",
		"platform/profiles/local/identity/credentials.yaml",
		"platform/profiles/local/identity/keycloak-reconcile.yaml",
		"platform/profiles/local/identity/vault-reconcile.yaml",
		"platform/profiles/local/identity/receipt.yaml",
		filepath.Join(clusterRoot, "platform-profile-identity.yaml"),
		"platform/profiles/local/prep/certificates/issuer.yaml",
		"platform/profiles/local/prep/certificates/root-certificate.yaml",
	} {
		if err := tree.Delete(relative); err != nil {
			return err
		}
	}
	statefulTemplate, err := tree.CandidateData(
		"platform/templates/secrets/stateful-values.yaml.tmpl",
	)
	if err != nil {
		return fmt.Errorf("read stateful values template: %w", err)
	}
	if err := tree.Set(
		"platform/profiles/local/prep/stateful-values.yaml",
		statefulTemplate,
	); err != nil {
		return err
	}
	for _, relative := range []string{
		"platform/profiles/local/access/certificates/kustomization.yaml",
	} {
		current, err := tree.YAML(relative)
		if err != nil {
			return err
		}
		resources, _ := current["resources"].([]any)
		additions := []string{}
		if strings.Contains(relative, "certificates") {
			additions = []string{"harbor-sso-ca.yaml", "keycloak-sso-ca.yaml", "vault-sso-ca.yaml"}
		}
		for _, addition := range additions {
			if !sliceContains(resources, addition) {
				resources = append(resources, addition)
			}
		}
		current["resources"] = resources
		if err := tree.SetYAML(relative, current); err != nil {
			return err
		}
	}
	return nil
}

func validateIdentityYAML(relative string, data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	documents := 0
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decode rendered identity manifest %s: %w", relative, err)
		}
		if len(document) == 0 || document["apiVersion"] == nil || document["kind"] == nil {
			return fmt.Errorf("rendered identity manifest %s contains an incomplete document", relative)
		}
		documents++
	}
	if documents == 0 {
		return fmt.Errorf("rendered identity manifest %s is empty", relative)
	}
	return nil
}

func newIdentityRenderContext(
	contract *identity.Contract,
	values map[string]any,
	localAccess *config.LocalAccess,
) (identityRenderContext, error) {
	if contract == nil {
		return identityRenderContext{}, errors.New("local identity contract is required for identity rendering")
	}
	if localAccess == nil {
		return identityRenderContext{}, errors.New("local access is required for identity rendering")
	}
	publicIngressCIDR, err := ipv4HostCIDR(
		"local public ingress VIP",
		localAccess.PublicIngressVIP,
	)
	if err != nil {
		return identityRenderContext{}, err
	}
	passthroughIngressCIDR, err := ipv4HostCIDR(
		"local passthrough ingress VIP",
		localAccess.PassthroughIngressVIP,
	)
	if err != nil {
		return identityRenderContext{}, err
	}
	valuesYAML, err := yaml.Marshal(values)
	if err != nil {
		return identityRenderContext{}, fmt.Errorf("encode generated identity values: %w", err)
	}
	configuration, err := operatorConfiguration(contract)
	if err != nil {
		return identityRenderContext{}, err
	}
	return identityRenderContext{
		Values:                 strings.TrimSuffix(string(valuesYAML), "\n"),
		PublicIngressCIDR:      publicIngressCIDR,
		PassthroughIngressCIDR: passthroughIngressCIDR,
		OperatorConfiguration: strings.TrimSuffix(
			string(configuration),
			"\n",
		),
	}, nil
}

func ipv4HostCIDR(label, value string) (string, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return "", fmt.Errorf("%s %q must be an IPv4 address", label, value)
	}
	return address.String() + "/32", nil
}

func operatorConfiguration(contract *identity.Contract) ([]byte, error) {
	admin := contract.Administrator()
	clients := contract.Clients()
	projected := make([]platformv1alpha1.KeycloakClient, len(clients))
	for index, client := range clients {
		kind := platformv1alpha1.ClientConfidential
		if client.Type == identity.PublicPKCE {
			kind = platformv1alpha1.ClientPublicPKCE
		}
		projected[index] = platformv1alpha1.KeycloakClient{
			ID: client.ID, Kind: kind,
			RedirectURIs: append([]string(nil), client.Callbacks...),
			WebOrigins:   []string{"https://" + client.Host},
			Audience:     client.Audience,
		}
	}
	vault, found := contract.ClientForApplication(identity.Vault)
	if !found {
		return nil, errors.New("identity contract has no Vault client")
	}
	configuration := platformv1alpha1.PlatformIdentityConfiguration{
		TypeMeta:   metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: "PlatformIdentityConfiguration"},
		ObjectMeta: metav1.ObjectMeta{Name: platformv1alpha1.SingletonName, Namespace: platformv1alpha1.SingletonNamespace},
		Spec: platformv1alpha1.PlatformIdentityConfigurationSpec{
			Domain: contract.Domain(),
			Keycloak: platformv1alpha1.KeycloakIntent{
				Realm: contract.Realm(),
				Administrator: platformv1alpha1.Administrator{
					Username: admin.Username, Group: admin.Group, RealmRole: admin.ServerRole,
				},
				GroupsScope: platformv1alpha1.GroupsScope{Name: "atum-groups", ClaimName: contract.GroupClaim()},
				Scopes:      contract.Scopes(),
				Clients:     projected,
			},
			Vault: platformv1alpha1.VaultIntent{
				AuthPath: "oidc",
				Policy: platformv1alpha1.VaultPolicy{
					Name:    "atum-admin",
					Purpose: platformv1alpha1.VaultPlatformAdministration,
				},
				Role: platformv1alpha1.VaultRole{
					Name: platformv1alpha1.VaultPlatformAdministrationRoleName, ClientID: vault.ID,
					RedirectURIs: append([]string(nil), vault.Callbacks...),
					Scopes:       contract.Scopes(), GroupsClaim: contract.GroupClaim(),
				},
				ExternalGroup: platformv1alpha1.VaultExternalGroup{
					Name: admin.Group, Claim: admin.Group, PolicyName: "atum-admin",
				},
			},
		},
	}
	data, err := sigsyaml.Marshal(configuration)
	if err != nil {
		return nil, fmt.Errorf("encode PlatformIdentityConfiguration: %w", err)
	}
	return data, nil
}

func identitySecretKey(id string) string {
	return strings.ToUpper(strings.ReplaceAll(id, "-", "_")) + "_CLIENT_SECRET"
}

func indentTemplate(spaces int, value string) string {
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	for index := range lines {
		lines[index] = prefix + lines[index]
	}
	return strings.Join(lines, "\n")
}

func sliceContains(values []any, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
