package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"atum/cli/config"
	"atum/cli/identity"

	"gopkg.in/yaml.v3"
)

const identityTemplateRoot = "platform/templates/identity"

type identityClientProjection struct {
	ID, EnvKey, Reference string
	Type                  string
	Callbacks             []string
	Origin                string
	Audience              bool
}

type identityRenderContext struct {
	SchemaVersion, Issuer, GroupClaim string
	Scopes                            []string
	Clients                           []identityClientProjection
	Confidential                      []identityClientProjection
	OpenBao                           identityClientProjection
	KeycloakImage, OpenBaoImage       string
	Values, Script, ClientDigest      string
	Namespace                         string
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

func identityValues(contract *identity.Contract) (map[string]any, error) {
	if contract == nil {
		return map[string]any{}, nil
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
	dnsEgress := map[string]any{
		"to": []any{map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{
				"kubernetes.io/metadata.name": "kube-system",
			}},
			"podSelector": map[string]any{"matchLabels": map[string]any{
				"k8s-app": "kube-dns",
			}},
		}},
		"ports": []any{
			map[string]any{"port": 53, "protocol": "TCP"},
			map[string]any{"port": 53, "protocol": "UDP"},
		},
	}
	harborSettings, err := json.Marshal(map[string]any{
		"auth_mode":                    "oidc_auth",
		"oidc_name":                    "Atum",
		"oidc_endpoint":                contract.Issuer(),
		"oidc_client_id":               harbor.ID,
		"oidc_client_secret":           secret(harbor),
		"oidc_scope":                   scopes,
		"oidc_verify_cert":             true,
		"oidc_auto_onboard":            true,
		"oidc_user_claim":              "preferred_username",
		"oidc_groups_claim":            contract.GroupClaim(),
		"oidc_admin_group":             admin.Group,
		"oidc_group_filter":            "",
		"oidc_extra_redirect_parms":    map[string]string{},
		"oidc_logout_endpoint_enabled": true,
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
			"logout_path":   "/",
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
			"certificateAuthority": map[string]any{
				"secretName": "atum-sso-ca",
			},
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
						"namespaceSelector": map[string]any{"matchLabels": map[string]any{
							"kubernetes.io/metadata.name": "istio-gateway",
						}},
						"podSelector": map[string]any{"matchLabels": map[string]any{
							"istio": "ingressgateway",
						}},
					}},
				},
			}},
		},
		"kiali": map[string]any{
			"sso": map[string]any{
				"enabled": true, "client_id": kiali.ID, "client_secret": secret(kiali),
			},
			"values": map[string]any{"upstream": map[string]any{"cr": map[string]any{
				"spec": map[string]any{"auth": map[string]any{"openid": map[string]any{
					"client_id": kiali.ID, "client_secret": secret(kiali),
					"issuer_uri": contract.Issuer(), "disable_rbac": true,
					"scopes": scopeList,
				}}},
			}}},
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
				"upstream": map[string]any{"ui": map[string]any{"openIDConnect": map[string]any{
					"enabled": true, "discoveryUrl": contract.Issuer() + "/.well-known/openid-configuration",
					"callbackUrl": reporter.Callbacks[0], "clientId": reporter.ID,
					"clientSecret": secret(reporter),
				}}},
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
			},
				"networkPolicies": map[string]any{"additionalPolicies": []any{map[string]any{
					"name": "allow-identity-reconcile-to-keycloak",
					"spec": map[string]any{
						"podSelector": map[string]any{"matchLabels": map[string]any{
							"atum.dev/identity-job": "keycloak",
						}},
						"policyTypes": []any{"Egress"},
						"egress": []any{
							dnsEgress,
							map[string]any{"to": []any{map[string]any{
								"namespaceSelector": map[string]any{"matchLabels": map[string]any{
									"kubernetes.io/metadata.name": "istio-gateway",
								}},
								"podSelector": map[string]any{"matchLabels": map[string]any{
									"istio": "ingressgateway",
								}},
							}}, "ports": []any{map[string]any{
								"port": 8443, "protocol": "TCP",
							}}},
						},
					},
				}}},
			}},
			"vault": map[string]any{"values": map[string]any{
				"istio": map[string]any{"serviceEntries": map[string]any{
					"custom": keycloakServiceEntries,
				}},
				"networkPolicies": map[string]any{
					"egress": map[string]any{"from": map[string]any{
						"vault": map[string]any{"to": map[string]any{"definition": map[string]any{
							"sso": true,
						}}},
					}},
					"additionalPolicies": []any{map[string]any{
						"name": "allow-openbao-identity-reconcile",
						"spec": map[string]any{
							"podSelector": map[string]any{"matchLabels": map[string]any{
								"atum.dev/identity-job": "openbao",
							}},
							"policyTypes": []any{"Egress"},
							"egress": []any{
								dnsEgress,
								map[string]any{
									"to": []any{map[string]any{"podSelector": map[string]any{
										"matchLabels": map[string]any{"app.kubernetes.io/name": "vault"},
									}}},
									"ports": []any{map[string]any{"port": 8200, "protocol": "TCP"}},
								},
								map[string]any{
									"to": []any{map[string]any{
										"namespaceSelector": map[string]any{"matchLabels": map[string]any{
											"kubernetes.io/metadata.name": "istio-system",
										}},
										"podSelector": map[string]any{"matchLabels": map[string]any{
											"app": "istiod",
										}},
									}},
									"ports": []any{map[string]any{"port": 15012, "protocol": "TCP"}},
								},
							},
						},
					}},
				},
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
						"gateways":  []any{"istio-gateway/public-ingressgateway"},
						"selectors": []any{map[string]any{"protect": "keycloak"}},
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

func configureIdentityValuesFrom(release map[string]any) error {
	valuesFrom := []any{
		map[string]any{
			"kind": "ConfigMap", "name": "bigbang-operational-values", "valuesKey": "values.yaml",
		},
		map[string]any{
			"kind": "ConfigMap", "name": "bigbang-generated-values", "valuesKey": "values.yaml",
		},
		map[string]any{
			"kind": "ConfigMap", "name": "bigbang-target-values", "valuesKey": "values.yaml",
		},
		map[string]any{
			"kind": "Secret", "name": "atum-platform-identity-values",
			"valuesKey": "values.yaml", "optional": true,
		},
		map[string]any{
			"kind": "Secret", "name": "atum-sso-ca", "valuesKey": "ca.crt",
			"targetPath": "sso.certificateAuthority.cert", "optional": true,
		},
	}
	if err := setNestedValue(release, "spec.valuesFrom", valuesFrom); err != nil {
		return fmt.Errorf("configure Big Bang identity values: %w", err)
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
	context, err := newIdentityRenderContext(desired, contract, identityValues)
	if err != nil {
		return err
	}
	clusterRoot := filepath.Join(desired.Platform.Directory, "clusters", desired.Project.Cluster)
	for _, name := range [...]string{"prep.yaml", "bigbang.yaml"} {
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
		if err := setCandidateYAML(tree, relative, current, candidate); err != nil {
			return fmt.Errorf("render explicit Flux defaults in %s: %w", relative, err)
		}
	}
	outputs := []identityOutput{
		{"cluster-root.yaml.tmpl", filepath.Join(clusterRoot, "kustomization.yaml"), nil},
		{"cluster-profile-prep.yaml.tmpl", filepath.Join(clusterRoot, "platform-profile-prep.yaml"), nil},
		{"cluster-profile-access.yaml.tmpl", filepath.Join(clusterRoot, "platform-profile-access.yaml"), nil},
		{"cluster-profile-identity.yaml.tmpl", filepath.Join(clusterRoot, "platform-profile-identity.yaml"), nil},
		{"local-prep-kustomization.yaml.tmpl", "platform/profiles/local/prep/kustomization.yaml", nil},
		{"cloud-prep-kustomization.yaml.tmpl", "platform/profiles/cloud/prep/kustomization.yaml", nil},
		{"identity-values.yaml.tmpl", "platform/profiles/local/prep/identity-values.yaml", nil},
		{"local-access-kustomization.yaml.tmpl", "platform/profiles/local/access/kustomization.yaml", nil},
		{"local-identity-kustomization.yaml.tmpl", "platform/profiles/local/identity/kustomization.yaml", nil},
		{"cloud-identity-kustomization.yaml.tmpl", "platform/profiles/cloud/identity/kustomization.yaml", nil},
		{"credentials.yaml.tmpl", "platform/profiles/local/identity/credentials.yaml", nil},
		{"receipt.yaml.tmpl", "platform/profiles/local/identity/receipt.yaml", nil},
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
	keycloakContext := context
	keycloakContext.Script = keycloakReconciliationScript(context)
	outputs = append(outputs, identityOutput{
		template: "keycloak-reconcile.yaml.tmpl",
		path:     "platform/profiles/local/identity/keycloak-reconcile.yaml",
		context:  func(identityRenderContext) any { return keycloakContext },
	})
	openBaoContext := context
	openBaoContext.Script = openBaoReconciliationScript(context)
	outputs = append(outputs, identityOutput{
		template: "openbao-reconcile.yaml.tmpl",
		path:     "platform/profiles/local/identity/openbao-reconcile.yaml",
		context:  func(identityRenderContext) any { return openBaoContext },
	})
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
	return validateGeneratedIdentityManifests(tree.Files(), desired, contract, identityValues)
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

func renderAndValidateIdentityCandidate(
	root string,
	files map[string][]byte,
	desired config.Document,
	contract *identity.Contract,
) error {
	values, err := identityValues(contract)
	if err != nil {
		return err
	}
	tree := newCandidateTree(root)
	for relative, data := range files {
		version := managedVersion{
			exists: true,
			mode:   0o644,
			digest: hashBytes(data),
			data:   append([]byte(nil), data...),
		}
		tree.originals[relative], tree.candidates[relative] = version, version
	}
	return renderIdentityManifests(tree, desired, contract, values)
}

func validateGeneratedIdentityManifests(
	files map[string][]byte,
	desired config.Document,
	contract *identity.Contract,
	values map[string]any,
) error {
	clusterRoot := filepath.ToSlash(filepath.Join(
		desired.Platform.Directory, "clusters", desired.Project.Cluster))
	if err := validateIdentityKustomization(
		files, clusterRoot+"/kustomization.yaml",
		[]string{
			"flux-system", "prep.yaml", "platform-profile-prep.yaml", "bigbang.yaml",
			"platform-profile-access.yaml", "platform-profile-identity.yaml",
		},
	); err != nil {
		return err
	}
	for _, expected := range []struct {
		file, name, path         string
		interval, retry, timeout string
		wait, force              bool
		dependency               string
		identitySource           bool
	}{
		{
			clusterRoot + "/platform-profile-prep.yaml",
			identity.ProfilePrepKustomizationName,
			"./platform/profiles/${ATUM_PLATFORM_PROFILE}/prep",
			"10m", "2m", "15m",
			true, false, "prep", true,
		},
		{
			clusterRoot + "/platform-profile-access.yaml",
			identity.ProfileAccessKustomizationName,
			"./platform/profiles/${ATUM_PLATFORM_PROFILE}/access",
			"10m", "2m", "15m",
			true, false, "bigbang", false,
		},
		{
			clusterRoot + "/platform-profile-identity.yaml",
			identity.ProfileIdentityKustomizationName,
			"./platform/profiles/${ATUM_PLATFORM_PROFILE}/identity",
			"10m", "2m", "20m",
			true, true, identity.ProfileAccessKustomizationName, true,
		},
	} {
		if err := validateIdentityFluxKustomization(files, expected.file, expected.name,
			expected.path, expected.interval, expected.retry, expected.timeout,
			expected.dependency, expected.wait, expected.force,
			expected.identitySource); err != nil {
			return err
		}
	}
	for _, expected := range []struct {
		path      string
		resources []string
	}{
		{
			"platform/profiles/local/prep/kustomization.yaml",
			[]string{"certificates", "load-balancer", "identity-values.yaml"},
		},
		{
			"platform/profiles/local/access/kustomization.yaml",
			[]string{"certificates"},
		},
		{
			"platform/profiles/local/identity/kustomization.yaml",
			[]string{
				"credentials.yaml", "keycloak-reconcile.yaml", "openbao-reconcile.yaml",
				"receipt.yaml",
			},
		},
	} {
		if err := validateIdentityKustomization(
			files, expected.path, expected.resources); err != nil {
			return err
		}
	}
	if err := validateEmptyIdentityKustomization(
		files, "platform/profiles/cloud/identity/kustomization.yaml"); err != nil {
		return err
	}
	if err := validateProfilePrepProjection(
		files, "platform/profiles/local/prep/kustomization.yaml", true); err != nil {
		return err
	}
	if err := validateProfilePrepProjection(
		files, "platform/profiles/cloud/prep/kustomization.yaml", false); err != nil {
		return err
	}
	if err := validateIdentityCAReferences(files); err != nil {
		return err
	}
	if err := validateIdentityValuesProjection(files, values); err != nil {
		return err
	}
	for _, namespace := range []string{"harbor", "keycloak", "vault"} {
		path := "platform/profiles/local/access/certificates/" + namespace + "-sso-ca.yaml"
		if err := validateIdentityCACarrier(files, path, namespace); err != nil {
			return err
		}
	}
	context, err := newIdentityRenderContext(desired, contract, values)
	if err != nil {
		return err
	}
	if err := validateIdentityCredentials(files, context); err != nil {
		return err
	}
	if err := validateIdentityJob(
		files, "platform/profiles/local/identity/keycloak-reconcile.yaml",
		identity.KeycloakJobNamespace, identity.KeycloakJobName, identity.KeycloakJobOwner,
		context, true,
	); err != nil {
		return err
	}
	if err := validateIdentityJob(
		files, "platform/profiles/local/identity/openbao-reconcile.yaml",
		identity.OpenBaoJobNamespace, identity.OpenBaoJobName, identity.OpenBaoJobOwner,
		context, false,
	); err != nil {
		return err
	}
	return validateIdentityReceipts(files, context)
}

func identityDocuments(files map[string][]byte, path string) ([]map[string]any, error) {
	data, found := files[path]
	if !found {
		return nil, fmt.Errorf("generated identity manifest %s is absent", path)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	documents := make([]map[string]any, 0, 2)
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return documents, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode generated identity manifest %s: %w", path, err)
		}
		if len(document) != 0 {
			documents = append(documents, document)
		}
	}
}

func singleIdentityDocument(files map[string][]byte, path string) (map[string]any, error) {
	documents, err := identityDocuments(files, path)
	if err != nil {
		return nil, err
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("generated identity manifest %s has %d documents, require one",
			path, len(documents))
	}
	return documents[0], nil
}

func validateIdentityKustomization(
	files map[string][]byte,
	path string,
	resources []string,
) error {
	document, err := singleIdentityDocument(files, path)
	if err != nil {
		return err
	}
	if document["apiVersion"] != "kustomize.config.k8s.io/v1beta1" ||
		document["kind"] != "Kustomization" ||
		!equalIdentityValue(document["resources"], stringValues(resources)) {
		return fmt.Errorf("generated identity Kustomization %s has an inexact resource contract", path)
	}
	return nil
}

func validateEmptyIdentityKustomization(files map[string][]byte, path string) error {
	document, err := singleIdentityDocument(files, path)
	if err != nil {
		return err
	}
	resources, found := document["resources"].([]any)
	if document["apiVersion"] != "kustomize.config.k8s.io/v1beta1" ||
		document["kind"] != "Kustomization" || !found || len(resources) != 0 {
		return fmt.Errorf("generated cloud identity Kustomization %s is not empty", path)
	}
	return nil
}

func validateProfilePrepProjection(
	files map[string][]byte,
	path string,
	local bool,
) error {
	document, err := singleIdentityDocument(files, path)
	if err != nil {
		return err
	}
	generators := mapSlice(document["configMapGenerator"])
	options := mapAt(document, "generatorOptions")
	if document["apiVersion"] != "kustomize.config.k8s.io/v1beta1" ||
		document["kind"] != "Kustomization" ||
		len(generators) != 1 || generators[0]["name"] != "bigbang-target-values" ||
		!equalIdentityValue(generators[0]["files"], []any{"values.yaml=values.yaml"}) ||
		options["disableNameSuffixHash"] != true ||
		mapAt(options, "labels")["reconcile.fluxcd.io/watch"] != "Enabled" {
		return fmt.Errorf("generated profile prep projection %s is inexact", path)
	}
	namespace, _ := document["namespace"].(string)
	generatorNamespace, _ := generators[0]["namespace"].(string)
	if local && generatorNamespace != "bigbang" || !local && namespace != "bigbang" {
		return fmt.Errorf("generated profile prep projection %s targets an inexact namespace", path)
	}
	return nil
}

func validateIdentityCAReferences(files map[string][]byte) error {
	document, err := singleIdentityDocument(
		files, "platform/profiles/local/access/certificates/kustomization.yaml")
	if err != nil {
		return err
	}
	if document["apiVersion"] != "kustomize.config.k8s.io/v1beta1" ||
		document["kind"] != "Kustomization" {
		return errors.New("generated certificate Kustomization has an inexact type")
	}
	expected := []string{
		"public-certificate.yaml",
		"keycloak-certificate.yaml",
		"harbor-sso-ca.yaml", "keycloak-sso-ca.yaml", "vault-sso-ca.yaml",
	}
	if !equalIdentityValue(document["resources"], stringValues(expected)) {
		return errors.New(
			"generated certificate Kustomization has an inexact ordered resource inventory")
	}
	return nil
}

func validateIdentityFluxKustomization(
	files map[string][]byte,
	path, name, resourcePath, interval, retry, timeout, dependency string,
	wait, force, identitySource bool,
) error {
	document, err := singleIdentityDocument(files, path)
	if err != nil {
		return err
	}
	metadata := mapAt(document, "metadata")
	spec := mapAt(document, "spec")
	source := mapAt(spec, "sourceRef")
	dependencies := mapSlice(spec["dependsOn"])
	actualForce, forceFound := spec["force"].(bool)
	if len(document) != 4 ||
		document["apiVersion"] != "kustomize.toolkit.fluxcd.io/v1" ||
		document["kind"] != "Kustomization" || metadata["name"] != name ||
		len(metadata) != 2 || metadata["namespace"] != "flux-system" ||
		len(spec) != 10 || spec["path"] != resourcePath ||
		spec["interval"] != interval || spec["retryInterval"] != retry ||
		spec["timeout"] != timeout ||
		spec["prune"] != true || spec["wait"] != wait ||
		!forceFound || actualForce != force || len(dependencies) != 1 ||
		len(dependencies[0]) != 1 || dependencies[0]["name"] != dependency ||
		len(source) != 2 || source["kind"] != "GitRepository" ||
		source["name"] != "flux-system" {
		return fmt.Errorf("generated Flux identity consumer %s has an inexact topology", path)
	}
	postBuild := mapAt(spec, "postBuild")
	substitute := mapAt(postBuild, "substitute")
	expectedPostBuildFields := 1
	if identitySource {
		expectedPostBuildFields++
	}
	if len(postBuild) != expectedPostBuildFields || len(substitute) != 1 ||
		substitute["ATUM_PLATFORM_DOMAIN"] != "${ATUM_PLATFORM_DOMAIN}" {
		return fmt.Errorf("generated Flux identity consumer %s omits the profile domain", path)
	}
	substitutions := mapSlice(postBuild["substituteFrom"])
	if identitySource {
		if len(substitutions) != 1 || len(substitutions[0]) != 3 ||
			substitutions[0]["kind"] != "Secret" ||
			substitutions[0]["name"] != "atum-platform-identity" ||
			substitutions[0]["optional"] != true {
			return fmt.Errorf("generated Flux identity consumer %s has an inexact identity handoff", path)
		}
	} else if len(substitutions) != 0 {
		return fmt.Errorf("generated Flux identity consumer %s has an unexpected identity handoff", path)
	}
	return nil
}

func validateIdentityValuesProjection(files map[string][]byte, values map[string]any) error {
	documents, err := identityDocuments(
		files, "platform/profiles/local/prep/identity-values.yaml")
	if err != nil {
		return err
	}
	if len(documents) != 2 {
		return fmt.Errorf("generated Big Bang identity projection has %d documents, require two",
			len(documents))
	}
	secret := documents[0]
	metadata := mapAt(secret, "metadata")
	stringData := mapAt(secret, "stringData")
	expectedValues, err := yaml.Marshal(values)
	if err != nil {
		return err
	}
	if secret["apiVersion"] != "v1" ||
		secret["kind"] != "Secret" || metadata["name"] != "atum-platform-identity-values" ||
		metadata["namespace"] != "bigbang" ||
		secret["type"] != "Opaque" || len(stringData) != 1 ||
		mapAt(metadata, "labels")["reconcile.fluxcd.io/watch"] != "Enabled" ||
		mapAt(metadata, "annotations")["atum.dev/identity-digest"] != "${ATUM_IDENTITY_DIGEST}" ||
		stringData["values.yaml"] != string(expectedValues) {
		return errors.New("generated Big Bang identity values Secret is inexact")
	}
	return validateIdentityCACertificate(documents[1], "bigbang")
}

func validateIdentityCACarrier(files map[string][]byte, path, namespace string) error {
	documents, err := identityDocuments(files, path)
	if err != nil {
		return err
	}
	if len(documents) != 1 {
		return fmt.Errorf("generated %s SSO CA carrier has %d documents, require one",
			namespace, len(documents))
	}
	return validateIdentityCACertificate(documents[0], namespace)
}

func validateIdentityCACertificate(certificate map[string]any, namespace string) error {
	metadata := mapAt(certificate, "metadata")
	spec := mapAt(certificate, "spec")
	issuer := mapAt(spec, "issuerRef")
	if certificate["apiVersion"] != "cert-manager.io/v1" ||
		certificate["kind"] != "Certificate" ||
		metadata["name"] != "atum-sso-ca" || metadata["namespace"] != namespace ||
		spec["secretName"] != "atum-sso-ca" || issuer["name"] != "atum-test-ca" ||
		issuer["kind"] != "ClusterIssuer" || issuer["group"] != "cert-manager.io" ||
		spec["commonName"] != "sso-ca."+namespace ||
		!equalIdentityValue(spec["dnsNames"], []any{"sso-ca." + namespace}) ||
		spec["duration"] != "8760h" || spec["renewBefore"] != "720h" {
		return fmt.Errorf("generated %s SSO CA carrier is inexact", namespace)
	}
	return nil
}

func validateIdentityCredentials(files map[string][]byte, context identityRenderContext) error {
	documents, err := identityDocuments(
		files, "platform/profiles/local/identity/credentials.yaml")
	if err != nil {
		return err
	}
	if len(documents) != 2 {
		return fmt.Errorf("generated identity credentials have %d documents, require two", len(documents))
	}
	keycloak, openBao := documents[0], documents[1]
	keycloakMetadata := mapAt(keycloak, "metadata")
	openBaoMetadata := mapAt(openBao, "metadata")
	if keycloak["apiVersion"] != "v1" ||
		keycloak["kind"] != "Secret" || keycloak["type"] != "Opaque" ||
		keycloakMetadata["name"] != "atum-keycloak-reconcile" ||
		keycloakMetadata["namespace"] != identity.KeycloakJobNamespace ||
		mapAt(keycloakMetadata, "annotations")["atum.dev/identity-digest"] != "${ATUM_IDENTITY_DIGEST}" ||
		openBao["apiVersion"] != "v1" ||
		openBao["kind"] != "Secret" || openBao["type"] != "Opaque" ||
		openBaoMetadata["name"] != "atum-openbao-reconcile" ||
		openBaoMetadata["namespace"] != identity.OpenBaoJobNamespace ||
		mapAt(openBaoMetadata, "annotations")["atum.dev/identity-digest"] != "${ATUM_IDENTITY_DIGEST}" {
		return errors.New("generated identity credential metadata is inexact")
	}
	keycloakData := mapAt(keycloak, "stringData")
	if len(keycloakData) != 4+len(context.Confidential) {
		return errors.New("generated Keycloak credentials have an inexact key set")
	}
	for _, expected := range []struct{ key, value string }{
		{"username", "${ATUM_IDENTITY_ADMIN_USERNAME}"},
		{"password", "${ATUM_IDENTITY_ADMIN_PASSWORD}"},
		{"group", "${ATUM_IDENTITY_ADMIN_GROUP}"},
		{"bootstrap-password", "${ATUM_IDENTITY_BOOTSTRAP_PASSWORD}"},
	} {
		if keycloakData[expected.key] != expected.value {
			return fmt.Errorf(
				"generated Keycloak credential %s is not a bootstrap reference", expected.key)
		}
	}
	for _, client := range context.Confidential {
		if keycloakData[client.ID] != client.Reference {
			return fmt.Errorf("generated Keycloak credentials omit client %s", client.ID)
		}
	}
	openBaoData := mapAt(openBao, "stringData")
	if len(openBaoData) != 3 || openBaoData["client-id"] != context.OpenBao.ID ||
		openBaoData["client-secret"] != context.OpenBao.Reference ||
		openBaoData["group"] != "${ATUM_IDENTITY_ADMIN_GROUP}" {
		return errors.New("generated OpenBao credentials are inexact")
	}
	return nil
}

func validateIdentityJob(
	files map[string][]byte,
	path, namespace, name, owner string,
	context identityRenderContext,
	keycloak bool,
) error {
	document, err := singleIdentityDocument(files, path)
	if err != nil {
		return err
	}
	metadata := mapAt(document, "metadata")
	spec := mapAt(document, "spec")
	template := mapAt(spec, "template")
	podMetadata := mapAt(template, "metadata")
	podSpec := mapAt(template, "spec")
	containers := mapSlice(podSpec["containers"])
	image, script := context.OpenBaoImage, openBaoReconciliationScript(context)
	if keycloak {
		image, script = context.KeycloakImage, keycloakReconciliationScript(context)
	}
	if document["apiVersion"] != "batch/v1" ||
		document["kind"] != "Job" || metadata["name"] != name ||
		metadata["namespace"] != namespace ||
		mapAt(metadata, "labels")["atum.dev/identity-job"] != owner ||
		mapAt(metadata, "annotations")["atum.dev/identity-digest"] != "${ATUM_IDENTITY_DIGEST}" ||
		len(spec) != 3 ||
		spec["backoffLimit"] != 2 || spec["activeDeadlineSeconds"] != 900 ||
		mapAt(podMetadata, "labels")["atum.dev/identity-job"] != owner ||
		mapAt(podMetadata, "annotations")["atum.dev/identity-digest"] != "${ATUM_IDENTITY_DIGEST}" ||
		podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" ||
		len(mapAt(podSpec, "securityContext")) != 2 ||
		mapAt(podSpec, "securityContext")["runAsNonRoot"] != true ||
		mapAt(mapAt(podSpec, "securityContext"), "seccompProfile")["type"] != "RuntimeDefault" ||
		podSpec["serviceAccountName"] != nil || podSpec["serviceAccount"] != nil ||
		len(podSpec) != 5 || len(containers) != 1 {
		return fmt.Errorf("generated identity Job %s has an inexact terminal contract", path)
	}
	container := containers[0]
	command := stringSlice(container["command"])
	expectedResources := map[string]any{
		"requests": map[string]any{"cpu": "25m", "memory": "32Mi"},
		"limits":   map[string]any{"cpu": "250m", "memory": "128Mi"},
	}
	if keycloak {
		expectedResources = map[string]any{
			"requests": map[string]any{"cpu": "25m", "memory": "64Mi"},
			"limits":   map[string]any{"cpu": "250m", "memory": "256Mi"},
		}
	}
	if len(container) != 8 ||
		container["image"] != image || container["imagePullPolicy"] != "IfNotPresent" ||
		len(command) != 3 ||
		command[0] != "/bin/sh" || command[1] != "-ceu" ||
		strings.TrimSpace(command[2]) != strings.TrimSpace(script) ||
		!equalIdentityValue(container["resources"], expectedResources) ||
		len(mapAt(container, "securityContext")) != 3 ||
		mapAt(container, "securityContext")["readOnlyRootFilesystem"] != true ||
		mapAt(container, "securityContext")["allowPrivilegeEscalation"] != false ||
		!equalIdentityValue(
			mapAt(mapAt(container, "securityContext"), "capabilities")["drop"],
			[]any{"ALL"},
		) {
		return fmt.Errorf("generated identity Job %s has an inexact execution contract", path)
	}
	if err := validateIdentityJobEnvironment(container, context, keycloak); err != nil {
		return fmt.Errorf("generated identity Job %s: %w", path, err)
	}
	if len(mapSlice(container["volumeMounts"])) != 1+boolInt(keycloak) ||
		!identityJobHasCAMount(container, podSpec) {
		return fmt.Errorf("generated identity Job %s has no exact CA mount", path)
	}
	volumes := mapSlice(podSpec["volumes"])
	hasEmptyDir := false
	for _, volume := range volumes {
		if volume["name"] == "kcadm" && len(mapAt(volume, "emptyDir")) != 0 {
			hasEmptyDir = true
		}
	}
	if hasEmptyDir != keycloak || len(volumes) != 1+boolInt(keycloak) {
		return fmt.Errorf("generated identity Job %s has an inexact writable config contract", path)
	}
	annotations := mapAt(podMetadata, "annotations")
	if keycloak {
		if annotations["sidecar.istio.io/inject"] != "false" {
			return fmt.Errorf("generated identity Job %s does not disable its unused sidecar", path)
		}
	} else if annotations["proxy.istio.io/config"] !=
		`{"holdApplicationUntilProxyStarts": true}` {
		return fmt.Errorf("generated identity Job %s does not wait for its mTLS sidecar", path)
	}
	return nil
}

func validateIdentityJobEnvironment(
	container map[string]any,
	context identityRenderContext,
	keycloak bool,
) error {
	type reference struct{ secret, key string }
	expected := map[string]reference{}
	literal := map[string]string{}
	if keycloak {
		expected["ADMIN_USERNAME"] = reference{"atum-keycloak-reconcile", "username"}
		expected["ADMIN_PASSWORD"] = reference{"atum-keycloak-reconcile", "password"}
		expected["ADMIN_GROUP"] = reference{"atum-keycloak-reconcile", "group"}
		expected["BOOTSTRAP_PASSWORD"] = reference{"atum-keycloak-reconcile", "bootstrap-password"}
		for _, client := range context.Confidential {
			expected[client.EnvKey] = reference{"atum-keycloak-reconcile", client.ID}
		}
	} else {
		literal["BAO_ADDR"] = "http://vault-vault.vault.svc:8200"
		expected["BAO_TOKEN"] = reference{"vault-token", "key"}
		expected["OIDC_CLIENT_ID"] = reference{"atum-openbao-reconcile", "client-id"}
		expected["OIDC_CLIENT_SECRET"] = reference{"atum-openbao-reconcile", "client-secret"}
		expected["ADMIN_GROUP"] = reference{"atum-openbao-reconcile", "group"}
	}
	environment := mapSlice(container["env"])
	if len(environment) != len(expected)+len(literal) {
		return errors.New("has an inexact environment key set")
	}
	for _, variable := range environment {
		name, _ := variable["name"].(string)
		if wanted, found := literal[name]; found {
			if variable["value"] != wanted {
				return fmt.Errorf("has an inexact literal environment value for %s", name)
			}
			delete(literal, name)
			continue
		}
		wanted, found := expected[name]
		reference := mapAt(mapAt(variable, "valueFrom"), "secretKeyRef")
		if !found || reference["name"] != wanted.secret || reference["key"] != wanted.key {
			return fmt.Errorf("has an inexact Secret reference for %s", name)
		}
		delete(expected, name)
	}
	if len(expected) != 0 || len(literal) != 0 {
		return errors.New("omits required environment keys")
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func identityJobHasCAMount(container, podSpec map[string]any) bool {
	mount := false
	for _, candidate := range mapSlice(container["volumeMounts"]) {
		if candidate["name"] == "ca" && candidate["mountPath"] == "/var/run/atum-ca" &&
			candidate["readOnly"] == true {
			mount = true
		}
	}
	volume := false
	for _, candidate := range mapSlice(podSpec["volumes"]) {
		secret := mapAt(candidate, "secret")
		items := mapSlice(secret["items"])
		if candidate["name"] == "ca" && secret["secretName"] == "atum-sso-ca" &&
			len(items) == 1 && items[0]["key"] == "ca.crt" && items[0]["path"] == "ca.crt" {
			volume = true
		}
	}
	return mount && volume
}

func validateIdentityReceipts(files map[string][]byte, context identityRenderContext) error {
	documents, err := identityDocuments(
		files, "platform/profiles/local/identity/receipt.yaml")
	if err != nil {
		return err
	}
	if len(documents) != 2 {
		return fmt.Errorf("generated identity receipts have %d documents, require two", len(documents))
	}
	for index, namespace := range []string{"keycloak", "vault"} {
		metadata := mapAt(documents[index], "metadata")
		data := mapAt(documents[index], "data")
		if documents[index]["apiVersion"] != "v1" ||
			documents[index]["kind"] != "ConfigMap" ||
			metadata["name"] != "atum-identity-contract" || metadata["namespace"] != namespace ||
			data["schemaVersion"] != context.SchemaVersion || data["issuer"] != context.Issuer ||
			data["digest"] != "${ATUM_IDENTITY_DIGEST}" ||
			data["clients"] != context.ClientDigest {
			return fmt.Errorf("generated %s identity receipt is inexact", namespace)
		}
	}
	return nil
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result
}

func newIdentityRenderContext(
	desired config.Document,
	contract *identity.Contract,
	values map[string]any,
) (identityRenderContext, error) {
	if contract == nil {
		return identityRenderContext{}, errors.New("local identity contract is required for identity rendering")
	}
	clients := contract.Clients()
	projected := make([]identityClientProjection, len(clients))
	confidential := make([]identityClientProjection, 0, len(clients))
	var openBao identityClientProjection
	openBaoFound := false
	for index, client := range clients {
		secretKey := identitySecretKey(client.ID)
		projection := identityClientProjection{
			ID: client.ID, EnvKey: secretKey, Reference: "${" + secretKey + "}",
			Type:      string(client.Type),
			Callbacks: append([]string(nil), client.Callbacks...),
			Origin:    "https://" + client.Host, Audience: client.Audience,
		}
		projected[index] = projection
		if client.Type == identity.Confidential {
			confidential = append(confidential, projection)
		}
		if client.Application == identity.OpenBao {
			openBao, openBaoFound = projection, true
		}
	}
	if !openBaoFound {
		return identityRenderContext{}, errors.New(
			"identity contract has no OpenBao application projection")
	}
	valuesYAML, err := yaml.Marshal(values)
	if err != nil {
		return identityRenderContext{}, fmt.Errorf("encode generated identity values: %w", err)
	}
	canonical := contract.Canonical()
	sum := sha256.Sum256(canonical)
	clear(canonical)
	keycloakImage := selectedImage(desired.Delivery.Images, "keycloak")
	openBaoImage := selectedImage(desired.Delivery.Images, "openbao")
	internalPrefix := strings.TrimSuffix(desired.Platform.Bootstrap.Registry.Host, "/") + "/atum/"
	if !strings.HasPrefix(keycloakImage, internalPrefix) ||
		!strings.HasPrefix(openBaoImage, internalPrefix) {
		return identityRenderContext{}, errors.New("identity reconciliation requires selected internal Keycloak and OpenBao images")
	}
	return identityRenderContext{
		SchemaVersion: contract.SchemaVersion(), Issuer: contract.Issuer(),
		GroupClaim: contract.GroupClaim(), Scopes: contract.Scopes(),
		Clients: projected, Confidential: confidential, OpenBao: openBao,
		KeycloakImage: keycloakImage,
		OpenBaoImage:  openBaoImage,
		Values:        string(valuesYAML), ClientDigest: hex.EncodeToString(sum[:]),
	}, nil
}

func selectedImage(images []config.Image, id string) string {
	for _, image := range images {
		if image.ID == id {
			return image.Target
		}
	}
	return ""
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

func keycloakReconciliationScript(context identityRenderContext) string {
	var script strings.Builder
	script.WriteString(`KCADM=/opt/keycloak/bin/kcadm.sh
CONFIG=/var/run/atum-kcadm/config
TRUSTSTORE=/var/run/atum-kcadm/truststore.p12
TRUSTPASS=atum-reconcile
SERVER=https://keycloak.${ATUM_PLATFORM_DOMAIN}/auth
CA=/var/run/atum-ca/ca.crt
ADMIN_EMAIL="$ADMIN_USERNAME@${ATUM_PLATFORM_DOMAIN}"
export KCADM_CONFIG="$CONFIG"
keytool -importcert -noprompt -alias atum-sso-ca -file "$CA" \
  -keystore "$TRUSTSTORE" -storetype PKCS12 -storepass "$TRUSTPASS" >/dev/null
"$KCADM" config truststore --config "$CONFIG" --trustpass "$TRUSTPASS" "$TRUSTSTORE" >/dev/null
login() {
  "$KCADM" config credentials --config "$CONFIG" --server "$SERVER" --realm master \
    --user "$1" --password "$2" >/dev/null 2>&1
}
until login "$ADMIN_USERNAME" "$ADMIN_PASSWORD" || login atum-bootstrap "$BOOTSTRAP_PASSWORD"; do
  sleep 5
done
group_id="$("$KCADM" get groups -r master -q search="$ADMIN_GROUP" --fields id,name --config "$CONFIG" |
  sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)"
if [ -z "$group_id" ]; then
  "$KCADM" create groups -r master -s name="$ADMIN_GROUP" --config "$CONFIG" >/dev/null
  group_id="$("$KCADM" get groups -r master -q search="$ADMIN_GROUP" --fields id,name --config "$CONFIG" |
    sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)"
fi
user_id="$("$KCADM" get users -r master -q username="$ADMIN_USERNAME" --fields id,username --config "$CONFIG" |
  sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)"
if [ -z "$user_id" ]; then
  "$KCADM" create users -r master -s username="$ADMIN_USERNAME" -s enabled=true \
    -s email="$ADMIN_EMAIL" -s emailVerified=true \
    -s firstName="$ADMIN_USERNAME" -s lastName=Administrator --config "$CONFIG" >/dev/null
  user_id="$("$KCADM" get users -r master -q username="$ADMIN_USERNAME" --fields id --config "$CONFIG" |
    sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)"
fi
"$KCADM" update users/"$user_id" -r master -s username="$ADMIN_USERNAME" -s enabled=true \
  -s email="$ADMIN_EMAIL" -s emailVerified=true \
  -s firstName="$ADMIN_USERNAME" -s lastName=Administrator --config "$CONFIG" >/dev/null
"$KCADM" set-password -r master --userid "$user_id" --new-password "$ADMIN_PASSWORD" \
  --config "$CONFIG" >/dev/null
"$KCADM" update users/"$user_id"/groups/"$group_id" -r master --config "$CONFIG" >/dev/null
management_id="$("$KCADM" get clients -r master -q clientId=realm-management --fields id --config "$CONFIG" |
  sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)"
[ -n "$management_id" ]
"$KCADM" add-roles -r master --uusername "$ADMIN_USERNAME" --cclientid realm-management \
  --rolename realm-admin --config "$CONFIG" >/dev/null
scope_ids="$("$KCADM" get client-scopes -r master --fields id,name --format csv --noquotes --config "$CONFIG" |
  sed -n '/,atum-groups$/s/,.*//p')"
scope_id="$(printf '%s\n' "$scope_ids" | head -1)"
if [ -z "$scope_id" ]; then
  "$KCADM" create client-scopes -r master -s name=atum-groups -s protocol=openid-connect \
    --config "$CONFIG" >/dev/null
  scope_id="$("$KCADM" get client-scopes -r master --fields id,name --format csv --noquotes --config "$CONFIG" |
    sed -n '/,atum-groups$/s/,.*//p' | head -1)"
fi
[ -n "$scope_id" ]
for duplicate_id in $scope_ids; do
  [ "$duplicate_id" = "$scope_id" ] ||
    "$KCADM" delete client-scopes/"$duplicate_id" -r master --config "$CONFIG" >/dev/null
done
[ "$("$KCADM" get client-scopes -r master --fields id,name --format csv --noquotes --config "$CONFIG" |
  grep -c ',atum-groups$')" -eq 1 ]
mapper_ids="$("$KCADM" get client-scopes/"$scope_id"/protocol-mappers/models -r master \
  --fields id,name --format csv --noquotes --config "$CONFIG" |
  sed -n '/,atum-groups$/s/,.*//p')"
mapper_id="$(printf '%s\n' "$mapper_ids" | head -1)"
`)
	fmt.Fprintf(&script, `mapper_resource=client-scopes/"$scope_id"/protocol-mappers/models
if [ -n "$mapper_id" ]; then
  mapper_resource="$mapper_resource/$mapper_id"
  mapper_action=update
else
  mapper_action=create
fi
"$KCADM" "$mapper_action" "$mapper_resource" -r master -s name=atum-groups \
  -s protocol=openid-connect -s protocolMapper=oidc-group-membership-mapper \
  -s 'config."full.path"=false' -s 'config."claim.name"=%s' \
  -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' \
  -s 'config."userinfo.token.claim"=true' --config "$CONFIG" >/dev/null
for duplicate_id in $mapper_ids; do
  [ "$duplicate_id" = "$mapper_id" ] ||
    "$KCADM" delete client-scopes/"$scope_id"/protocol-mappers/models/"$duplicate_id" \
      -r master --config "$CONFIG" >/dev/null
done
[ "$("$KCADM" get client-scopes/"$scope_id"/protocol-mappers/models -r master \
  --fields id,name --format csv --noquotes --config "$CONFIG" |
  grep -c ',atum-groups$')" -eq 1 ]
`, context.GroupClaim)
	for _, client := range context.Clients {
		public := client.Type == string(identity.PublicPKCE)
		secretArg := ""
		if !public {
			secretArg = fmt.Sprintf(" -s secret=\"$%s\"", client.EnvKey)
		}
		callbacks := shellJSON(client.Callbacks)
		origins := shellJSON([]string{client.Origin})
		fmt.Fprintf(&script, `client_id=$("$KCADM" get clients -r master -q clientId=%s --fields id --config "$CONFIG" |
  sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)
if [ -z "$client_id" ]; then
  "$KCADM" create clients -r master -s clientId=%s -s enabled=true -s protocol=openid-connect \
    -s publicClient=%t -s standardFlowEnabled=true -s directAccessGrantsEnabled=false \
    -s 'redirectUris=%s' -s 'webOrigins=%s'%s --config "$CONFIG" >/dev/null
  client_id=$("$KCADM" get clients -r master -q clientId=%s --fields id --config "$CONFIG" |
    sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)
else
  "$KCADM" update clients/"$client_id" -r master -s enabled=true -s protocol=openid-connect \
    -s publicClient=%t -s standardFlowEnabled=true -s directAccessGrantsEnabled=false \
    -s 'redirectUris=%s' -s 'webOrigins=%s'%s --config "$CONFIG" >/dev/null
fi
`, client.ID, client.ID, public, callbacks, origins, secretArg, client.ID,
			public, callbacks, origins, secretArg)
		if public {
			script.WriteString(`"$KCADM" update clients/"$client_id" -r master \
  -s 'attributes."pkce.code.challenge.method"=S256' --config "$CONFIG" >/dev/null
`)
		} else {
			fmt.Fprintf(&script, `actual_secret=$("$KCADM" get clients/"$client_id"/client-secret -r master \
  --fields value --config "$CONFIG" | sed -n 's/.*"value" : "\([^"]*\)".*/\1/p' | head -1)
[ "$actual_secret" = "$%s" ]
`, client.EnvKey)
		}
		script.WriteString(`"$KCADM" update clients/"$client_id"/default-client-scopes/"$scope_id" \
  -r master --config "$CONFIG" >/dev/null
`)
		for _, scope := range context.Scopes {
			if scope == "openid" || scope == "groups" {
				continue
			}
			fmt.Fprintf(&script, `builtin_scope_id=$("$KCADM" get client-scopes -r master --fields id,name \
  --format csv --noquotes --config "$CONFIG" | sed -n '/,%s$/s/,.*//p' | head -1)
[ -n "$builtin_scope_id" ]
"$KCADM" update clients/"$client_id"/default-client-scopes/"$builtin_scope_id" \
  -r master --config "$CONFIG" >/dev/null
"$KCADM" get clients/"$client_id"/default-client-scopes -r master --fields name \
  --config "$CONFIG" | grep -F '"name" : "%s"' >/dev/null
`, scope, scope)
		}
		fmt.Fprintf(&script, `audience_ids=$("$KCADM" get clients/"$client_id"/protocol-mappers/models -r master \
  --fields id,name --format csv --noquotes --config "$CONFIG" |
  sed -n '/,atum-audience$/s/,.*//p')
audience_id="$(printf '%%s\n' "$audience_ids" | head -1)"
`)
		if client.Audience {
			fmt.Fprintf(&script, `if [ -n "$audience_id" ]; then
  audience_resource=clients/"$client_id"/protocol-mappers/models/"$audience_id"
  audience_action=update
else
  audience_resource=clients/"$client_id"/protocol-mappers/models
  audience_action=create
fi
"$KCADM" "$audience_action" "$audience_resource" -r master \
  -s name=atum-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
  -s 'config."included.client.audience"=%s' -s 'config."id.token.claim"=true' \
  -s 'config."access.token.claim"=true' --config "$CONFIG" >/dev/null
for duplicate_id in $audience_ids; do
  [ "$duplicate_id" = "$audience_id" ] ||
    "$KCADM" delete clients/"$client_id"/protocol-mappers/models/"$duplicate_id" \
      -r master --config "$CONFIG" >/dev/null
done
[ "$("$KCADM" get clients/"$client_id"/protocol-mappers/models -r master \
  --fields id,name --format csv --noquotes --config "$CONFIG" |
  grep -c ',atum-audience$')" -eq 1 ]
`, client.ID)
			script.WriteString(`"$KCADM" get clients/"$client_id"/protocol-mappers/models -r master \
  --config "$CONFIG" | grep -F '"included.client.audience" : "'"$client_id"'"' >/dev/null
`)
		} else {
			script.WriteString(`for audience_id in $audience_ids; do
  "$KCADM" delete clients/"$client_id"/protocol-mappers/models/"$audience_id" \
    -r master --config "$CONFIG" >/dev/null
done
[ "$("$KCADM" get clients/"$client_id"/protocol-mappers/models -r master \
  --fields id,name --format csv --noquotes --config "$CONFIG" |
  grep -c ',atum-audience$' || true)" -eq 0 ]
`)
		}
		fmt.Fprintf(&script, `verified=$("$KCADM" get clients/"$client_id" -r master --fields clientId,publicClient,redirectUris,webOrigins,attributes --config "$CONFIG")
printf '%%s' "$verified" | grep -F '"clientId" : "%s"' >/dev/null
printf '%%s' "$verified" | grep -F '"publicClient" : %t' >/dev/null
"$KCADM" get clients/"$client_id"/default-client-scopes -r master --fields name --config "$CONFIG" |
  grep -F '"name" : "atum-groups"' >/dev/null
`, client.ID, public)
		for _, callback := range client.Callbacks {
			fmt.Fprintf(&script, `printf '%%s' "$verified" | grep -F %s >/dev/null
`, shellQuote(callback))
		}
		fmt.Fprintf(&script, `printf '%%s' "$verified" | grep -F %s >/dev/null
`, shellQuote(client.Origin))
		if public {
			script.WriteString(`printf '%s' "$verified" | grep -F '"pkce.code.challenge.method" : "S256"' >/dev/null
`)
		}
	}
	script.WriteString(`login "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
bootstrap_id=$("$KCADM" get users -r master -q username=atum-bootstrap --fields id --config "$CONFIG" |
  sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -1)
if [ -n "$bootstrap_id" ]; then
  "$KCADM" delete users/"$bootstrap_id" -r master --config "$CONFIG"
fi
login "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
verified_user=$("$KCADM" get users/"$user_id" -r master \
  --fields username,email,emailVerified,enabled --config "$CONFIG")
printf '%s' "$verified_user" | grep -F '"username" : "'"$ADMIN_USERNAME"'"' >/dev/null
printf '%s' "$verified_user" | grep -F '"email" : "'"$ADMIN_EMAIL"'"' >/dev/null
printf '%s' "$verified_user" | grep -F '"emailVerified" : true' >/dev/null
printf '%s' "$verified_user" | grep -F '"enabled" : true' >/dev/null
"$KCADM" get users/"$user_id"/groups -r master --fields id,name --config "$CONFIG" |
  grep -F '"name" : "'"$ADMIN_GROUP"'"' >/dev/null
"$KCADM" get users/"$user_id"/role-mappings/clients/"$management_id" -r master --config "$CONFIG" |
  grep -F '"name" : "realm-admin"' >/dev/null
`)
	return script.String()
}

func openBaoReconciliationScript(context identityRenderContext) string {
	callback := context.OpenBao.Callbacks[0]
	return fmt.Sprintf(`trap 'curl -fsS -X POST http://127.0.0.1:15020/quitquitquit >/dev/null 2>&1 || true' EXIT
until bao status >/dev/null 2>&1; do sleep 5; done
list_ids() {
  bao list -format=json "$1" 2>/dev/null |
    sed -n 's/.*"keys":[[]\([^]]*\)[]].*/\1/p' | tr -d '"' | tr ',' ' '
}
if ! bao auth list -format=json | grep -F '"oidc/"' >/dev/null; then
  bao auth enable -path=oidc oidc >/dev/null
fi
bao write auth/oidc/config \
  oidc_discovery_url=%s \
  oidc_discovery_ca=@/var/run/atum-ca/ca.crt \
  oidc_client_id="$OIDC_CLIENT_ID" \
  oidc_client_secret="$OIDC_CLIENT_SECRET" \
  default_role=atum-admin >/dev/null
bao policy write atum-admin - >/dev/null <<'POLICY'
path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"]
}
POLICY
bao write auth/oidc/role/atum-admin \
  bound_audiences="$OIDC_CLIENT_ID" \
  allowed_redirect_uris=%s \
  user_claim=preferred_username \
  groups_claim=%s \
  oidc_scopes=%s \
  policies=atum-admin >/dev/null
accessor=$(bao auth list -format=json |
  sed -n '/"oidc\\/"/,/}/s/.*"accessor": *"\([^"]*\)".*/\1/p' | head -1)
[ -n "$accessor" ]
group_id=$(
  for id in $(list_ids identity/group/id); do
    [ -n "$id" ] || continue
    [ "$(bao read -field=name identity/group/id/"$id" 2>/dev/null || true)" = "$ADMIN_GROUP" ] && {
      printf '%%s' "$id"
      break
    }
  done)
if [ -z "$group_id" ]; then
  group_id=$(bao write -field=id identity/group name="$ADMIN_GROUP" type=external policies=atum-admin)
else
  bao write identity/group/id/"$group_id" name="$ADMIN_GROUP" type=external policies=atum-admin >/dev/null
fi
alias_id=$(
  for id in $(list_ids identity/group-alias/id); do
    [ -n "$id" ] || continue
    name=$(bao read -field=name identity/group-alias/id/"$id" 2>/dev/null || true)
    mount=$(bao read -field=mount_accessor identity/group-alias/id/"$id" 2>/dev/null || true)
    [ "$name" = "$ADMIN_GROUP" ] && [ "$mount" = "$accessor" ] && {
      printf '%%s' "$id"
      break
    }
  done)
if [ -z "$alias_id" ]; then
  bao write identity/group-alias name="$ADMIN_GROUP" mount_accessor="$accessor" \
    canonical_id="$group_id" >/dev/null
else
  bao write identity/group-alias/id/"$alias_id" name="$ADMIN_GROUP" mount_accessor="$accessor" \
    canonical_id="$group_id" >/dev/null
fi
[ "$(bao read -field=policies identity/group/id/"$group_id" | tr -d '[]')" = "atum-admin" ]
[ "$(bao read -field=oidc_discovery_url auth/oidc/config)" = %s ]
[ "$(bao read -field=oidc_client_id auth/oidc/config)" = "$OIDC_CLIENT_ID" ]
bao read -format=json auth/oidc/role/atum-admin | grep -F %s >/dev/null
[ "$(bao read -field=user_claim auth/oidc/role/atum-admin)" = "preferred_username" ]
[ "$(bao read -field=groups_claim auth/oidc/role/atum-admin)" = "%s" ]
`, shellQuote(context.Issuer), shellQuote(callback), shellQuote(context.GroupClaim),
		shellQuote(strings.Join(context.Scopes, ",")), shellQuote(context.Issuer),
		shellQuote(callback), context.GroupClaim)
}

func shellJSON(values []string) string {
	data, _ := json.Marshal(values)
	return string(data)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func sortedClientIDs(contract *identity.Contract) []string {
	clients := contract.Clients()
	result := make([]string, len(clients))
	for index := range clients {
		result[index] = clients[index].ID
	}
	sort.Strings(result)
	return result
}

func validatePlatformIdentityContract(
	artifacts []chartArtifact,
	contract *identity.Contract,
	desired config.Document,
	kubernetesVersion string,
	files map[string][]byte,
	root string,
) error {
	if contract == nil {
		return errors.New("canonical local identity contract is unavailable")
	}
	if err := renderAndValidateIdentityCandidate(root, files, desired, contract); err != nil {
		return fmt.Errorf("generated identity manifest contract: %w", err)
	}
	var umbrella *chartArtifact
	packagePaths := make(map[string]string, len(artifacts))
	for index := range artifacts {
		switch {
		case artifacts[index].ID == "bigbang":
			umbrella = &artifacts[index]
		case strings.HasPrefix(artifacts[index].ID, "package/"):
			packagePaths[strings.TrimPrefix(artifacts[index].ID, "package/")] =
				artifacts[index].CandidatePath
		}
	}
	if umbrella == nil {
		return errors.New("identity compatibility has no Big Bang artifact")
	}
	collector := newReleaseValueCollector("bigbang").captureResources()
	for _, source := range umbrella.CandidateSources {
		if err := collector.observe(source); err != nil {
			return fmt.Errorf("observe identity source: %w", err)
		}
	}
	if _, err := renderChart(
		umbrella.CandidatePath, kubernetesVersion, umbrella.CandidateValues,
		collector, releaseOptions("bigbang", "bigbang"), nil,
	); err != nil {
		return fmt.Errorf("render identity umbrella: %w", err)
	}
	releases, err := collector.valuesForArtifacts(umbrella.CandidateBindings)
	if err != nil {
		return fmt.Errorf("resolve identity package values: %w", err)
	}
	require := func(packageID, path string, expected any) error {
		instances := releases[packageID]
		if len(instances) != 1 {
			return fmt.Errorf("identity package %s rendered %d release instances, require one",
				packageID, len(instances))
		}
		actual, found := nestedValue(instances[0].values, path)
		if !found || !equalIdentityValue(actual, expected) {
			return fmt.Errorf("identity package %s does not render exact %s", packageID, path)
		}
		return nil
	}
	admin := contract.Administrator()
	headlamp, _ := contract.ClientForApplication(identity.Headlamp)
	kiali, _ := contract.ClientForApplication(identity.Kiali)
	grafana, _ := contract.ClientForApplication(identity.Grafana)
	reporter, _ := contract.ClientForApplication(identity.PolicyReporter)
	keycloakHost := strings.TrimSuffix(
		strings.TrimPrefix(contract.Issuer(), "https://"), "/auth/realms/master")
	checks := []struct {
		pkg, path string
		value     any
	}{
		{"headlamp", "upstream.config.oidc.clientID", headlamp.ID},
		{"headlamp", "upstream.config.oidc.usePKCE", true},
		{"headlamp", "upstream.config.oidc.secret.create", false},
		{"headlamp", "upstream.clusterRoleBinding.create", false},
		{"headlamp", "bigbang.rbac.enabled", true},
		{"kiali", "sso.enabled", true},
		{"kiali", "upstream.cr.spec.auth.strategy", "openid"},
		{"kiali", "upstream.cr.spec.auth.openid.client_id", kiali.ID},
		{"kiali", "upstream.cr.spec.auth.openid.disable_rbac", true},
		{"grafana", "sso.enabled", true},
		{"grafana", "upstream.grafana\\.ini.auth.generic_oauth.enabled", true},
		{"grafana", "upstream.grafana\\.ini.auth.generic_oauth.role_attribute_path",
			fmt.Sprintf("contains(groups[*], '%s') && '%s' || 'Viewer'",
				admin.Group, grafana.AdministratorMapping)},
		{"kyverno-reporter", "upstream.ui.openIDConnect.enabled", true},
		{"harbor", "upstream.caBundleSecretName", "atum-sso-ca"},
		{"keycloak", "upstream.secrets.env.stringData.KEYCLOAK_ADMIN", "atum-bootstrap"},
		{"vault", "upstream.server.extraEnvironmentVars.VAULT_CACERT",
			"/var/run/atum-sso/ca.crt"},
		{"vault", "networkPolicies.egress.from.vault.to.definition.sso", true},
	}
	for _, check := range checks {
		if err := require(check.pkg, check.path, check.value); err != nil {
			return err
		}
	}
	if len(reporter.Callbacks) == 0 {
		return errors.New("identity contract has no Policy Reporter callback")
	}
	if err := require("kyverno-reporter", "upstream.ui.openIDConnect.callbackUrl",
		reporter.Callbacks[0]); err != nil {
		return err
	}
	headlampValues := releases["headlamp"][0].values
	bindings, found := nestedValue(headlampValues, "bigbang.rbac.clusterRoleBindings")
	if !found || !containsHeadlampAdminBinding(bindings, "oidc:"+admin.Group) {
		return errors.New("Headlamp does not render the canonical administrator group binding")
	}
	if containsInsecureIdentitySetting(umbrella.CandidateValues) {
		return errors.New("identity values enable insecure certificate verification")
	}
	if err := validateAuthserviceIdentityChains(
		packagePaths["authservice"], kubernetesVersion, releases["authservice"], contract,
	); err != nil {
		return err
	}
	if err := validateHarborIdentityChart(
		packagePaths["harbor"], kubernetesVersion, releases["harbor"],
		contract,
	); err != nil {
		return err
	}
	if err := validateVaultIdentityChart(
		packagePaths["vault"], kubernetesVersion, releases["vault"], keycloakHost,
	); err != nil {
		return err
	}
	if err := validateKeycloakIdentityChart(
		packagePaths["keycloak"], kubernetesVersion, releases["keycloak"],
	); err != nil {
		return err
	}
	keycloakPolicies, found := nestedValue(
		releases["keycloak"][0].values, "networkPolicies.additionalPolicies")
	if !found || !containsIdentityReconcilePolicy(keycloakPolicies) {
		return errors.New("Keycloak package does not render the identity reconciliation egress policy")
	}
	openBaoPolicies, found := nestedValue(
		releases["vault"][0].values, "networkPolicies.additionalPolicies")
	if !found || !containsOpenBaoIdentityPolicy(openBaoPolicies) {
		return errors.New("OpenBao package does not render the identity reconciliation egress policy")
	}
	if !renderedResourceContains(
		collector.rendered, "Secret", "gitlab", "gitlab-sso-provider",
		`"admin_groups":[`+fmt.Sprintf("%q", admin.Group)+`]`,
	) {
		return errors.New("GitLab does not render the canonical administrator group")
	}
	for _, id := range sortedClientIDs(contract) {
		client, _ := contract.Client(id)
		if client.Integration == identity.FluxReconciliation {
			continue
		}
		if !containsRenderedClientIdentity(collector.rendered, client) {
			return fmt.Errorf("Big Bang identity rendering omits client %s", id)
		}
	}
	renderContext, err := newIdentityRenderContext(desired, contract, map[string]any{})
	if err != nil {
		return err
	}
	keycloakScript := keycloakReconciliationScript(renderContext)
	for _, client := range contract.Clients() {
		for _, callback := range client.Callbacks {
			if !strings.Contains(keycloakScript, callback) {
				return fmt.Errorf("Keycloak reconciliation omits callback %s", callback)
			}
		}
	}
	for _, imageID := range []string{"keycloak", "openbao"} {
		image := selectedImage(desired.Delivery.Images, imageID)
		if image == "" || !strings.HasPrefix(image,
			desired.Platform.Bootstrap.Registry.Host+"/atum/") {
			return fmt.Errorf("identity reconciliation image %s is not selected from the internal registry", imageID)
		}
	}
	if err := validateIdentityExecutableContracts(desired.Delivery.Images, files); err != nil {
		return err
	}
	return nil
}

func validateIdentityExecutableContracts(images []config.Image, files map[string][]byte) error {
	var keycloak, openBao *config.Image
	for index := range images {
		switch images[index].ID {
		case "keycloak":
			keycloak = &images[index]
		case "openbao":
			openBao = &images[index]
		}
	}
	if keycloak == nil || keycloak.Delivery.Default.Type != "mirror" ||
		!strings.HasPrefix(keycloak.Delivery.Default.Source, "quay.io/keycloak/keycloak:") {
		return errors.New("selected Keycloak image does not prove the /opt/keycloak/bin/kcadm.sh contract")
	}
	if openBao == nil || openBao.Delivery.Default.Type != "build" ||
		openBao.Delivery.Default.BakeTarget != "openbao" ||
		!containsString(openBao.Delivery.Default.Materials, "platform/build/docker") ||
		!containsString(openBao.Delivery.Default.Materials, "platform/build/compat/openbao") {
		return errors.New("selected OpenBao image does not prove the bao executable contract")
	}
	dockerfile := string(files["platform/build/docker/Dockerfile.data"])
	if !strings.Contains(dockerfile, "FROM data-runtime AS openbao") ||
		!strings.Contains(dockerfile, "apt-get install --no-install-recommends -y bash curl procps") ||
		!strings.Contains(dockerfile, "COPY --from=openbao-build /out/bao /usr/local/bin/vault") ||
		!strings.Contains(dockerfile, "RUN ln -s vault /usr/local/bin/bao") {
		return errors.New("selected OpenBao build does not install the bao executable")
	}
	return nil
}

func validateAuthserviceIdentityChains(
	path, kubernetesVersion string,
	instances []releaseValueInstance,
	contract *identity.Contract,
) error {
	if path == "" || len(instances) != 1 {
		return fmt.Errorf("Authservice rendered %d release instances, require one", len(instances))
	}
	raw, found := nestedValue(instances[0].values, "chains")
	chains, ok := raw.(map[string]any)
	if !found || !ok {
		return errors.New("Authservice does not render its identity chains")
	}
	if placeholder, found := chains["local"]; !found || placeholder != nil {
		return errors.New("Authservice does not explicitly remove the placeholder localhost chain")
	}
	expected := 0
	for _, client := range contract.Clients() {
		if client.Integration != identity.Authservice {
			continue
		}
		expected++
		name := string(client.Application)
		chain, _ := chains[name].(map[string]any)
		if chain["client_id"] != client.ID || chain["callback_uri"] != client.Callbacks[0] {
			return fmt.Errorf("Authservice chain %s does not match the canonical client", name)
		}
		match, _ := chain["match"].(map[string]any)
		if match["header"] != ":authority" || match["prefix"] != client.Host {
			return fmt.Errorf("Authservice chain %s does not match host %s", name, client.Host)
		}
	}
	if len(chains) != expected+1 {
		return fmt.Errorf("Authservice rendered %d chain values, require %d clients and one deletion",
			len(chains), expected)
	}
	rendered := newReleaseValueCollector("authservice").captureResources()
	if _, err := renderChart(
		path, kubernetesVersion, instances[0].values, rendered,
		releaseOptions(instances[0].name, instances[0].namespace),
		instances[0].renderers,
	); err != nil {
		return fmt.Errorf("render Authservice identity contract: %w", err)
	}
	var text string
	for _, resource := range rendered.rendered {
		if resource.key.kind != "Secret" || resource.key.namespace != instances[0].namespace ||
			resource.key.name != "authservice" {
			continue
		}
		stringData, _ := resource.object["stringData"].(map[string]any)
		text, _ = stringData["config.json"].(string)
		break
	}
	if text == "" {
		return errors.New("selected Authservice chart does not render its configuration Secret")
	}
	for _, placeholder := range []string{"localhost", "local_id", "local_secret"} {
		if strings.Contains(text, placeholder) {
			return fmt.Errorf("selected Authservice chart retains placeholder %s", placeholder)
		}
	}
	for _, client := range contract.Clients() {
		if client.Integration != identity.Authservice {
			continue
		}
		if !strings.Contains(text, client.ID) || !strings.Contains(text, client.Callbacks[0]) {
			return fmt.Errorf("selected Authservice chart omits canonical client %s", client.ID)
		}
	}
	return nil
}

func nestedValue(root map[string]any, path string) (any, bool) {
	components := splitNestedPath(path)
	current := any(root)
	for _, component := range components {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[component]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func splitNestedPath(path string) []string {
	components := make([]string, 0, strings.Count(path, ".")+1)
	var current strings.Builder
	escaped := false
	for _, character := range path {
		switch {
		case escaped:
			current.WriteRune(character)
			escaped = false
		case character == '\\':
			escaped = true
		case character == '.':
			components = append(components, current.String())
			current.Reset()
		default:
			current.WriteRune(character)
		}
	}
	components = append(components, current.String())
	return components
}

func equalIdentityValue(actual, expected any) bool {
	actualData, actualErr := json.Marshal(actual)
	expectedData, expectedErr := json.Marshal(expected)
	return actualErr == nil && expectedErr == nil && bytes.Equal(actualData, expectedData)
}

func containsHeadlampAdminBinding(raw any, group string) bool {
	bindings, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range bindings {
		binding, _ := item.(map[string]any)
		if binding["roleRef"] != "cluster-admin" {
			continue
		}
		subjects, _ := binding["subjects"].([]any)
		for _, subjectValue := range subjects {
			subject, _ := subjectValue.(map[string]any)
			if subject["kind"] == "Group" && subject["name"] == group &&
				subject["apiGroup"] == "rbac.authorization.k8s.io" {
				return true
			}
		}
	}
	return false
}

func containsInsecureIdentitySetting(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))
			if normalized == "insecureskipverify" || normalized == "tlsinsecureskipverify" ||
				normalized == "oidcverifycert" {
				if enabled, ok := nested.(bool); ok &&
					((normalized == "oidcverifycert" && !enabled) ||
						(normalized != "oidcverifycert" && enabled)) {
					return true
				}
			}
			if containsInsecureIdentitySetting(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsInsecureIdentitySetting(nested) {
				return true
			}
		}
	}
	return false
}

func validateHarborIdentityChart(
	path, kubernetesVersion string,
	instances []releaseValueInstance,
	contract *identity.Contract,
) error {
	if path == "" || len(instances) != 1 {
		return errors.New("Harbor identity contract has no exact selected package release")
	}
	rendered := newReleaseValueCollector("harbor").captureResources()
	if _, err := renderChart(
		path, kubernetesVersion, instances[0].values, rendered,
		releaseOptions(instances[0].name, instances[0].namespace),
		instances[0].renderers,
	); err != nil {
		return fmt.Errorf("render Harbor identity contract: %w", err)
	}
	var overwrite string
	for _, resource := range rendered.rendered {
		if resource.key.kind != "Secret" {
			continue
		}
		data, _ := resource.object["data"].(map[string]any)
		encoded, _ := data["CONFIG_OVERWRITE_JSON"].(string)
		if encoded != "" {
			decoded, err := decodeBase64String(encoded)
			if err != nil {
				return fmt.Errorf("decode Harbor CONFIG_OVERWRITE_JSON: %w", err)
			}
			overwrite = decoded
			break
		}
	}
	if overwrite == "" {
		return errors.New("selected Harbor chart does not render CONFIG_OVERWRITE_JSON")
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(overwrite), &settings); err != nil {
		return fmt.Errorf("decode Harbor identity settings: %w", err)
	}
	admin := contract.Administrator()
	harbor, found := contract.ClientForApplication(identity.Harbor)
	if !found {
		return errors.New("identity contract has no Harbor client")
	}
	expected := map[string]any{
		"auth_mode": "oidc_auth", "oidc_endpoint": contract.Issuer(),
		"oidc_client_id": harbor.ID, "oidc_scope": strings.Join(contract.Scopes(), " "),
		"oidc_client_secret": "${" + identitySecretKey(harbor.ID) + "}",
		"oidc_verify_cert":   true, "oidc_auto_onboard": true,
		"oidc_user_claim": "preferred_username", "oidc_groups_claim": contract.GroupClaim(),
		"oidc_admin_group": admin.Group,
	}
	for key, value := range expected {
		if !equalIdentityValue(settings[key], value) {
			return fmt.Errorf("Harbor CONFIG_OVERWRITE_JSON has inexact %s", key)
		}
	}
	text := renderedObjectsText(rendered.rendered)
	if !strings.Contains(text, "atum-sso-ca") ||
		!strings.Contains(text, "ca-bundle") && !strings.Contains(text, "caBundle") {
		return errors.New("selected Harbor chart does not mount the configured SSO CA bundle")
	}
	return nil
}

func validateVaultIdentityChart(
	path, kubernetesVersion string,
	instances []releaseValueInstance,
	keycloakHost string,
) error {
	if path == "" || len(instances) != 1 {
		return errors.New("OpenBao identity contract has no exact selected package release")
	}
	rendered := newReleaseValueCollector("vault").captureResources()
	if _, err := renderChart(
		path, kubernetesVersion, instances[0].values, rendered,
		releaseOptions(instances[0].name, instances[0].namespace),
		instances[0].renderers,
	); err != nil {
		return fmt.Errorf("render OpenBao identity contract: %w", err)
	}
	text := renderedObjectsText(rendered.rendered)
	for _, required := range []string{
		"atum-sso-ca", "/var/run/atum-sso", keycloakHost, `"kind":"ServiceEntry"`,
	} {
		if !strings.Contains(text, required) {
			return fmt.Errorf("selected OpenBao chart does not render identity trust field %s", required)
		}
	}
	return nil
}

func validateKeycloakIdentityChart(
	path, kubernetesVersion string,
	instances []releaseValueInstance,
) error {
	if path == "" || len(instances) != 1 {
		return errors.New("Keycloak identity contract has no exact selected package release")
	}
	rendered := newReleaseValueCollector("keycloak").captureResources()
	if _, err := renderChart(
		path, kubernetesVersion, instances[0].values, rendered,
		releaseOptions(instances[0].name, instances[0].namespace),
		instances[0].renderers,
	); err != nil {
		return fmt.Errorf("render Keycloak identity contract: %w", err)
	}
	text := renderedObjectsText(rendered.rendered)
	for _, required := range []string{"atum-bootstrap", "allow-identity-reconcile-to-keycloak"} {
		if !strings.Contains(text, required) {
			return fmt.Errorf("selected Keycloak chart does not render identity field %s", required)
		}
	}
	return nil
}

func containsIdentityReconcilePolicy(raw any) bool {
	policies, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, policyValue := range policies {
		policy, _ := policyValue.(map[string]any)
		if policy["name"] != "allow-identity-reconcile-to-keycloak" {
			continue
		}
		spec, _ := policy["spec"].(map[string]any)
		if !exactLabelSelector(spec["podSelector"], "atum.dev/identity-job", "keycloak") {
			continue
		}
		for _, rule := range mapSlice(spec["egress"]) {
			if !hasExactPort(rule["ports"], 8443, "TCP") {
				continue
			}
			for _, destination := range mapSlice(rule["to"]) {
				if exactLabelSelector(destination["namespaceSelector"],
					"kubernetes.io/metadata.name", "istio-gateway") &&
					exactLabelSelector(destination["podSelector"], "istio", "ingressgateway") {
					return true
				}
			}
		}
	}
	return false
}

func containsOpenBaoIdentityPolicy(raw any) bool {
	policies, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, policyValue := range policies {
		policy, _ := policyValue.(map[string]any)
		if policy["name"] != "allow-openbao-identity-reconcile" {
			continue
		}
		spec, _ := policy["spec"].(map[string]any)
		if !exactLabelSelector(spec["podSelector"], "atum.dev/identity-job", "openbao") {
			continue
		}
		vault, istiod, dnsTCP, dnsUDP := false, false, false, false
		for _, rule := range mapSlice(spec["egress"]) {
			for _, destination := range mapSlice(rule["to"]) {
				switch {
				case exactAppSelector(destination["podSelector"], "vault") &&
					hasExactPort(rule["ports"], 8200, "TCP"):
					vault = true
				case exactLabelSelector(destination["namespaceSelector"],
					"kubernetes.io/metadata.name", "istio-system") &&
					exactLabelSelector(destination["podSelector"], "app", "istiod") &&
					hasExactPort(rule["ports"], 15012, "TCP"):
					istiod = true
				case exactLabelSelector(destination["namespaceSelector"],
					"kubernetes.io/metadata.name", "kube-system") &&
					exactLabelSelector(destination["podSelector"], "k8s-app", "kube-dns"):
					dnsTCP, dnsUDP = exactDNSPorts(rule["ports"])
				}
			}
		}
		return vault && istiod && dnsTCP && dnsUDP
	}
	return false
}

func exactDNSPorts(raw any) (bool, bool) {
	ports := mapSlice(raw)
	if len(ports) != 2 {
		return false, false
	}
	tcp, udp := false, false
	for _, port := range ports {
		if portNumber(port["port"]) != 53 {
			return false, false
		}
		switch stringAt(port, "protocol") {
		case "TCP":
			tcp = true
		case "UDP":
			udp = true
		default:
			return false, false
		}
	}
	return tcp, udp
}

func decodeBase64String(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func renderedResourceContains(
	resources []renderedResource,
	kind, namespace, name, wanted string,
) bool {
	for _, resource := range resources {
		if resource.key.kind != kind || resource.key.namespace != namespace ||
			resource.key.name != name {
			continue
		}
		data, err := json.Marshal(resource.object)
		return err == nil && strings.Contains(strings.ReplaceAll(string(data), " ", ""), wanted)
	}
	return false
}

func containsRenderedClientIdentity(resources []renderedResource, client identity.Client) bool {
	text := renderedObjectsText(resources)
	if !strings.Contains(text, client.ID) {
		return false
	}
	if client.Integration == identity.Authservice {
		for _, callback := range client.Callbacks {
			if !strings.Contains(text, callback) {
				return false
			}
		}
	}
	return true
}

func renderedObjectsText(resources []renderedResource) string {
	var result strings.Builder
	for _, resource := range resources {
		encoded, err := json.Marshal(resource.object)
		if err == nil {
			result.Write(encoded)
		}
	}
	return result.String()
}
