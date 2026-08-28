package update

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPlatformValuesKeepNativeOpenSearchSecurityAndLocalFacts(t *testing.T) {
	t.Parallel()

	operationalText, operational := readPlatformValues(t, "platform/apps/bigbang/values.yaml")
	localText, local := readPlatformValues(t, "platform/profiles/local/prep/values.yaml")
	template := readPlatformText(t, "platform/profiles/local/access/opensearch-secrets.yaml")
	secretDocuments := readPlatformDocuments(
		t, "platform/profiles/local/access/opensearch-secrets.yaml",
	)
	certificates := readPlatformText(
		t, "platform/profiles/local/prep/certificates/opensearch-certificate.yaml",
	)
	certificateDocuments := readPlatformDocuments(
		t, "platform/profiles/local/prep/certificates/opensearch-certificate.yaml",
	)
	access := readPlatformText(t, "platform/clusters/atum/platform-profile-access.yaml")
	accessValues := readPlatformDocuments(
		t, "platform/clusters/atum/platform-profile-access.yaml",
	)[0]
	certificateValues := readPlatformDocuments(
		t, "platform/clusters/atum/platform-certificates.yaml",
	)[0]
	bigBangValues := readPlatformDocuments(t, "platform/clusters/atum/bigbang.yaml")[0]
	clusterRoot := readPlatformDocuments(t, "platform/clusters/atum/kustomization.yaml")[0]

	if _, found := mapAt(operational, "packages", "opensearch", "values")["singleNode"]; found {
		t.Fatal("target-independent OpenSearch values contain local sizing")
	}
	openSearch := mapAt(operational, "packages", "opensearch", "values")
	if err := validateNativeOpenSearchShape(
		operational, local, secretDocuments, certificateDocuments, accessValues,
	); err != nil {
		t.Fatal(err)
	}
	if !namedReference(
		mapAt(certificateValues, "spec")["dependsOn"].([]any), "bigbang",
	) || namedReference(
		mapAt(bigBangValues, "spec")["dependsOn"].([]any), "platform-profile-access",
	) {
		t.Fatal("Flux OpenSearch dependency graph is cyclic or incomplete")
	}
	healthChecks := mapSlice(mapAt(bigBangValues, "spec")["healthChecks"])
	if len(healthChecks) != 2 ||
		healthChecks[0]["name"] != "bigbang" ||
		healthChecks[0]["namespace"] != "bigbang" ||
		healthChecks[1]["name"] != "cert-manager" ||
		healthChecks[1]["namespace"] != "cert-manager" {
		t.Fatal("Big Bang readiness gate does not target its real HelmRelease namespaces")
	}
	resources, _ := clusterRoot["resources"].([]any)
	if !stringReference(resources, "platform-certificates.yaml") ||
		!stringReference(resources, "platform-profile-access.yaml") {
		t.Fatal("Flux root omits OpenSearch certificate or access layers")
	}
	for _, defaultValue := range []string{"protocol", "clusterName", "networkHost"} {
		if _, found := openSearch[defaultValue]; found {
			t.Fatalf("OpenSearch repeats selected chart default %s", defaultValue)
		}
	}
	if strings.Contains(operationalText, "DISABLE_SECURITY_PLUGIN") ||
		strings.Contains(operationalText, "allow-fluentbit-opensearch-to-anywhere") {
		t.Fatal("obsolete or broad OpenSearch security exception remains")
	}
	fluentPolicy := mapAt(
		operational, "fluentbit", "values", "networkPolicies", "egress",
		"from", "fluent-bit", "to", "k8s", "opensearch/opensearch:9200",
	)
	fluentSourceSelector := mapAt(
		operational, "fluentbit", "values", "networkPolicies", "egress",
		"from", "fluent-bit", "podSelector", "matchLabels",
	)
	if fluentPolicy["enabled"] != true ||
		fluentSourceSelector["app.kubernetes.io/name"] != "fluent-bit" ||
		fluentSourceSelector["app.kubernetes.io/instance"] != "fluentbit" ||
		mapAt(fluentPolicy, "podSelector", "matchLabels")["app.kubernetes.io/name"] !=
			"opensearch" ||
		mapAt(fluentPolicy, "podSelector", "matchLabels")["app.kubernetes.io/instance"] != "opensearch" {
		t.Fatal("Fluent Bit does not declare its exact OpenSearch egress")
	}
	if _, found := mapAt(local, "fluentbit", "values")["networkPolicies"]; found {
		t.Fatal("local profile duplicates target-independent Fluent Bit policy")
	}
	openSearchPackage := mapAt(operational, "packages", "opensearch")
	if len(mapSlice(mapAt(openSearchPackage, "network")["additionalPolicies"])) != 1 ||
		len(mapSlice(
			mapAt(openSearchPackage, "istio", "hardened")["customAuthorizationPolicies"],
		)) != 1 {
		t.Fatal("OpenSearch does not declare the coupled wrapper transport policies")
	}
	localOpenSearch := mapAt(local, "packages", "opensearch", "values")
	if localOpenSearch["singleNode"] != true || localOpenSearch["replicas"] != 1 {
		t.Fatal("local OpenSearch profile does not contain the singleton sizing override")
	}
	outputs, _ := mapAt(operational, "fluentbit", "values", "upstream", "config")["outputs"].(string)
	for _, required := range []string{
		"HTTP_User           ${OPENSEARCH_USER}",
		"HTTP_Passwd         ${OPENSEARCH_PASSWORD}",
		"tls                 On",
		"tls.verify          On", "tls.ca_file",
	} {
		if !strings.Contains(outputs, required) {
			t.Fatalf("Fluent Bit output is missing %q", required)
		}
	}
	if strings.Contains(outputs, "$${OPENSEARCH_") {
		t.Fatal("Fluent Bit output escapes a runtime environment reference")
	}
	if !strings.Contains(access, "name: atum-platform-stateful") ||
		!strings.Contains(access, "name: platform-certificates") {
		t.Fatal("post-Big-Bang access layer does not consume the stateful projection after certificates")
	}
	if strings.Contains(outputs, "tls                 Off") ||
		strings.Contains(outputs, "http://") {
		t.Fatal("Fluent Bit permits unauthenticated HTTP to OpenSearch")
	}
	for _, required := range []string{
		"name: opensearch-security-config",
		"name: opensearch-admin-credentials",
		"name: opensearch-dashboards-credentials",
		"name: fluentbit-opensearch-credentials",
		"${ATUM_STATEFUL_OPENSEARCH_ADMIN_HASH}",
		"${ATUM_STATEFUL_OPENSEARCH_DASHBOARDS_HASH}",
		"${ATUM_STATEFUL_FLUENTBIT_OPENSEARCH_HASH}",
		"anonymous_auth_enabled: false",
	} {
		if !strings.Contains(template, required) {
			t.Fatalf("stateful security projection is missing %q", required)
		}
	}
	if strings.Contains(template, "admin: admin") ||
		strings.Contains(template, "password: admin") {
		t.Fatal("stateful security projection contains a demo credential")
	}
	for _, required := range []string{
		"secretName: opensearch-node-tls",
		"opensearch-cluster-master.opensearch.svc.cluster.local",
		"*.opensearch-cluster-master-headless.opensearch.svc.cluster.local",
	} {
		if !strings.Contains(certificates, required) {
			t.Fatalf("certificate intent is missing %q", required)
		}
	}

	network := mapAt(local, "networkPolicies")
	if network["controlPlaneCidr"] != "10.77.0.8/29" {
		t.Fatalf("API destination = %v", network["controlPlaneCidr"])
	}
	for _, gateway := range []string{"public", "passthrough"} {
		service := mapAt(
			local,
			"istioGateway",
			"values",
			"gateways",
			gateway,
			"upstream",
			"service",
		)
		if service["externalTrafficPolicy"] != "Local" {
			t.Fatalf(
				"%s gateway external traffic policy = %v",
				gateway,
				service["externalTrafficPolicy"],
			)
		}
	}
	for _, policy := range []string{
		"add-default-securitycontext",
		"require-non-root-user",
		"require-non-root-group",
		"restrict-volume-types",
	} {
		if !policyExcludesResource(
			local, policy, "local-path-storage", "helper-pod-*",
		) {
			t.Fatalf(
				"Kyverno policy %s does not narrowly exclude the local-path helper",
				policy,
			)
		}
	}
	for _, absent := range []string{
		"vpcCidr:", "10.77.0.0/24",
		"allow-egress-from-.*-wait-job-to-anywhere-any-port",
		"controlPlaneWebhooks",
		"public-ingressgateway:[8080,8443]",
	} {
		if strings.Contains(localText, absent) {
			t.Fatalf("removed authored patch or broad range %q remains", absent)
		}
	}
}

func TestNativeOpenSearchShapeRejectsSecurityDrift(t *testing.T) {
	t.Parallel()
	_, operational := readPlatformValues(t, "platform/apps/bigbang/values.yaml")
	_, local := readPlatformValues(t, "platform/profiles/local/prep/values.yaml")
	secrets := readPlatformDocuments(t, "platform/profiles/local/access/opensearch-secrets.yaml")
	certificates := readPlatformDocuments(
		t, "platform/profiles/local/prep/certificates/opensearch-certificate.yaml",
	)
	access := readPlatformDocuments(t, "platform/clusters/atum/platform-profile-access.yaml")[0]

	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any, []map[string]any, []map[string]any, map[string]any)
	}{
		{
			name: "whole directory security mount",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				mapAt(values, "packages", "opensearch", "values", "securityConfig")["config"] =
					map[string]any{"securityConfigSecret": "opensearch-security-config"}
			},
		},
		{
			name: "missing file reference",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				delete(
					mapAt(values, "packages", "opensearch", "values", "securityConfig"),
					"rolesMappingSecret",
				)
			},
		},
		{
			name: "role user mismatch",
			mutate: func(_ map[string]any, _ map[string]any, documents []map[string]any, _ []map[string]any, _ map[string]any) {
				data := mapAt(secretByName(documents, "opensearch-security-config"), "stringData")
				data["roles_mapping.yml"] = strings.ReplaceAll(
					data["roles_mapping.yml"].(string), "kibana_server", "dashboard_server",
				)
			},
		},
		{
			name: "anonymous access",
			mutate: func(_ map[string]any, _ map[string]any, documents []map[string]any, _ []map[string]any, _ map[string]any) {
				data := mapAt(secretByName(documents, "opensearch-security-config"), "stringData")
				data["config.yml"] = strings.ReplaceAll(
					data["config.yml"].(string), "anonymous_auth_enabled: false",
					"anonymous_auth_enabled: true",
				)
			},
		},
		{
			name: "mutable install input",
			mutate: func(_ map[string]any, _ map[string]any, documents []map[string]any, _ []map[string]any, _ map[string]any) {
				delete(secretByName(documents, "opensearch-security-config"), "immutable")
			},
		},
		{
			name: "consumer client key",
			mutate: func(_ map[string]any, _ map[string]any, documents []map[string]any, _ []map[string]any, _ map[string]any) {
				mapAt(secretByName(documents, "opensearch-dashboards-ca"), "data")["tls.key"] = "unused"
			},
		},
		{
			name: "native reload disabled",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "packages", "opensearch", "values", "config")
				config["opensearch.yml"] = strings.ReplaceAll(
					config["opensearch.yml"].(string),
					"plugins.security.ssl.certificates_hot_reload.enabled: true",
					"plugins.security.ssl.certificates_hot_reload.enabled: false",
				)
			},
		},
		{
			name: "transport CA path",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "packages", "opensearch", "values", "config")
				config["opensearch.yml"] = strings.ReplaceAll(
					config["opensearch.yml"].(string),
					"plugins.security.ssl.transport.pemtrustedcas_filepath: certificates/ca.crt",
					"plugins.security.ssl.transport.pemtrustedcas_filepath: certificates/other.crt",
				)
			},
		},
		{
			name: "removed HTTP TLS field",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "packages", "opensearch", "values", "config")
				config["opensearch.yml"] = strings.ReplaceAll(
					config["opensearch.yml"].(string),
					"plugins.security.ssl.http.enabled: true\n", "",
				)
			},
		},
		{
			name: "node identity",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "packages", "opensearch", "values", "config")
				config["opensearch.yml"] = strings.ReplaceAll(
					config["opensearch.yml"].(string), "CN=opensearch-node", "CN=other-node",
				)
			},
		},
		{
			name: "node certificate issuer",
			mutate: func(_ map[string]any, _ map[string]any, _ []map[string]any, certificates []map[string]any, _ map[string]any) {
				mapAt(certificates[0], "spec", "issuerRef")["name"] = "other-ca"
			},
		},
		{
			name: "node certificate SAN",
			mutate: func(_ map[string]any, _ map[string]any, _ []map[string]any, certificates []map[string]any, _ map[string]any) {
				mapAt(certificates[0], "spec")["dnsNames"] = []any{"opensearch-cluster-master"}
			},
		},
		{
			name: "node certificate usage",
			mutate: func(_ map[string]any, _ map[string]any, _ []map[string]any, certificates []map[string]any, _ map[string]any) {
				mapAt(certificates[0], "spec")["usages"] = []any{"server auth"}
			},
		},
		{
			name: "demo security enabled",
			mutate: func(_ map[string]any, local map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				environments := mapAt(local, "packages", "opensearch", "values")["extraEnvs"].([]any)
				environments[0].(map[string]any)["value"] = "false"
			},
		},
		{
			name: "writer privilege expansion",
			mutate: func(_ map[string]any, _ map[string]any, documents []map[string]any, _ []map[string]any, _ map[string]any) {
				data := mapAt(secretByName(documents, "opensearch-security-config"), "stringData")
				data["roles.yml"] = strings.ReplaceAll(
					data["roles.yml"].(string), "cluster_composite_ops", "cluster_all",
				)
			},
		},
		{
			name: "Dashboards HTTP endpoint",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				dashboards := mapAt(values, "packages", "opensearch-dashboards", "values")
				dashboards["opensearchHosts"] =
					"http://opensearch-cluster-master.opensearch.svc.cluster.local:9200"
			},
		},
		{
			name: "Dashboards credential Secret",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				mapAt(values, "packages", "opensearch-dashboards", "values", "opensearchAccount")["secret"] =
					"other-credentials"
			},
		},
		{
			name: "Dashboards verification",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "packages", "opensearch-dashboards", "values", "config")
				config["opensearch_dashboards.yml"] = strings.ReplaceAll(
					config["opensearch_dashboards.yml"].(string), "verificationMode: full",
					"verificationMode: none",
				)
			},
		},
		{
			name: "Dashboards CA mount",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				mounts := mapAt(values, "packages", "opensearch-dashboards", "values")["secretMounts"].([]any)
				mounts[0].(map[string]any)["secretName"] = "other-ca"
			},
		},
		{
			name: "Fluent Bit credential Secret",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				environment := mapAt(values, "fluentbit", "values", "upstream")["envFrom"].([]any)
				mapAt(environment[0].(map[string]any), "secretRef")["name"] = "other-credentials"
			},
		},
		{
			name: "Fluent Bit credential key",
			mutate: func(_ map[string]any, _ map[string]any, documents []map[string]any, _ []map[string]any, _ map[string]any) {
				credentials := mapAt(
					secretByName(documents, "fluentbit-opensearch-credentials"), "stringData",
				)
				credentials["PASSWORD"] = credentials["OPENSEARCH_PASSWORD"]
				delete(credentials, "OPENSEARCH_PASSWORD")
			},
		},
		{
			name: "Fluent Bit escaped interpolation",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "fluentbit", "values", "upstream", "config")
				config["outputs"] = strings.ReplaceAll(
					config["outputs"].(string), "${OPENSEARCH_USER}", "$${OPENSEARCH_USER}",
				)
			},
		},
		{
			name: "Fluent Bit TLS removed",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "fluentbit", "values", "upstream", "config")
				config["outputs"] = strings.ReplaceAll(
					config["outputs"].(string), "tls                 On\n", "",
				)
			},
		},
		{
			name: "Fluent Bit TLS verification",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "fluentbit", "values", "upstream", "config")
				config["outputs"] = strings.ReplaceAll(
					config["outputs"].(string), "tls.verify          On", "tls.verify          Off",
				)
			},
		},
		{
			name: "Fluent Bit CA path",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "fluentbit", "values", "upstream", "config")
				config["outputs"] = strings.ReplaceAll(
					config["outputs"].(string), "/fluent-bit/tls/ca.crt", "/fluent-bit/tls/other.crt",
				)
			},
		},
		{
			name: "Fluent Bit endpoint",
			mutate: func(values map[string]any, _ map[string]any, _ []map[string]any, _ []map[string]any, _ map[string]any) {
				config := mapAt(values, "fluentbit", "values", "upstream", "config")
				config["outputs"] = strings.ReplaceAll(
					config["outputs"].(string),
					"opensearch-cluster-master.opensearch.svc.cluster.local", "other.opensearch",
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := cloneMap(operational)
			localCopy := cloneMap(local)
			secretCopies := cloneDocuments(secrets)
			certificateCopies := cloneDocuments(certificates)
			accessCopy := cloneMap(access)
			test.mutate(values, localCopy, secretCopies, certificateCopies, accessCopy)
			if err := validateNativeOpenSearchShape(
				values, localCopy, secretCopies, certificateCopies, accessCopy,
			); err == nil {
				t.Fatal("invalid native-security shape was accepted")
			}
		})
	}
}

func validateNativeOpenSearchShape(
	operational map[string]any,
	local map[string]any,
	documents []map[string]any,
	certificates []map[string]any,
	access map[string]any,
) error {
	openSearch := mapAt(operational, "packages", "opensearch", "values")
	security := mapAt(openSearch, "securityConfig")
	if _, found := security["config"]; found {
		return errors.New("whole-directory OpenSearch security mount is forbidden")
	}
	for _, key := range []string{
		"actionGroupsSecret", "configSecret", "internalUsersSecret",
		"rolesSecret", "rolesMappingSecret", "tenantsSecret",
	} {
		if security[key] != "opensearch-security-config" {
			return fmt.Errorf("OpenSearch security reference %s is missing or renamed", key)
		}
	}
	configValues, err := decodeInlineYAML(mapAt(openSearch, "config")["opensearch.yml"])
	if err != nil || len(configValues) != 11 {
		return errors.New("OpenSearch TLS configuration is incomplete or contains an unowned field")
	}
	for key, expected := range map[string]any{
		"plugins.security.ssl.transport.pemcert_filepath":              "certificates/tls.crt",
		"plugins.security.ssl.transport.pemkey_filepath":               "certificates/tls.key",
		"plugins.security.ssl.transport.pemtrustedcas_filepath":        "certificates/ca.crt",
		"plugins.security.ssl.transport.enforce_hostname_verification": true,
		"plugins.security.ssl.http.enabled":                            true,
		"plugins.security.ssl.http.pemcert_filepath":                   "certificates/tls.crt",
		"plugins.security.ssl.http.pemkey_filepath":                    "certificates/tls.key",
		"plugins.security.ssl.http.pemtrustedcas_filepath":             "certificates/ca.crt",
		"plugins.security.ssl.certificates_hot_reload.enabled":         true,
		"plugins.security.allow_default_init_securityindex":            true,
	} {
		if configValues[key] != expected {
			return fmt.Errorf("OpenSearch TLS setting %s drifted", key)
		}
	}
	if !exactStrings(configValues["plugins.security.nodes_dn"], "CN=opensearch-node") {
		return errors.New("OpenSearch node identity drifted")
	}
	mounts, _ := openSearch["secretMounts"].([]any)
	if len(mounts) != 1 ||
		mounts[0].(map[string]any)["name"] != "opensearch-node-tls" ||
		mounts[0].(map[string]any)["secretName"] != "opensearch-node-tls" ||
		mounts[0].(map[string]any)["path"] != "/usr/share/opensearch/config/certificates" ||
		mounts[0].(map[string]any)["subPath"] != nil {
		return errors.New("OpenSearch node certificate mount is not atomic")
	}
	environments, _ := mapAt(local, "packages", "opensearch", "values")["extraEnvs"].([]any)
	if len(environments) != 1 ||
		environments[0].(map[string]any)["name"] != "DISABLE_INSTALL_DEMO_CONFIG" ||
		environments[0].(map[string]any)["value"] != "true" {
		return errors.New("OpenSearch demo security installation is not disabled")
	}

	securitySecret := secretByName(documents, "opensearch-security-config")
	if securitySecret["immutable"] != true {
		return errors.New("OpenSearch security configuration is mutable")
	}
	data := mapAt(securitySecret, "stringData")
	for _, key := range []string{
		"action_groups.yml", "config.yml", "internal_users.yml",
		"roles.yml", "roles_mapping.yml", "tenants.yml",
	} {
		if _, found := data[key]; !found {
			return fmt.Errorf("OpenSearch security file %s is missing", key)
		}
	}
	if len(data) != 6 {
		return errors.New("OpenSearch security Secret contains an unowned file")
	}
	securityValues, err := decodeInlineYAML(data["config.yml"])
	if err != nil ||
		mapAt(securityValues, "config", "dynamic", "http")["anonymous_auth_enabled"] != false ||
		mapAt(securityValues, "config", "dynamic", "authc")["basic_internal_auth_domain"] == nil {
		return errors.New("OpenSearch anonymous authentication is not disabled")
	}
	users, err := decodeInlineYAML(data["internal_users.yml"])
	if err != nil || len(users) != 4 {
		return errors.New("OpenSearch internal users are incomplete or contain a demo user")
	}
	for _, pair := range [][2]string{
		{"admin", "${ATUM_STATEFUL_OPENSEARCH_ADMIN_HASH}"},
		{"kibanaserver", "${ATUM_STATEFUL_OPENSEARCH_DASHBOARDS_HASH}"},
		{"fluentbit", "${ATUM_STATEFUL_FLUENTBIT_OPENSEARCH_HASH}"},
	} {
		if mapAt(users, pair[0])["hash"] != pair[1] {
			return errors.New("OpenSearch user/hash pairing is incomplete")
		}
	}
	if mapAt(users, "admin")["reserved"] != true ||
		!exactStrings(mapAt(users, "admin")["backend_roles"], "admin") ||
		mapAt(users, "kibanaserver")["reserved"] != true ||
		mapAt(users, "fluentbit")["reserved"] != true ||
		!exactStrings(mapAt(users, "fluentbit")["backend_roles"], "fluentbit_writer") {
		return errors.New("OpenSearch user identities or backend roles drifted")
	}
	mappings, err := decodeInlineYAML(data["roles_mapping.yml"])
	if err != nil || len(mappings) != 4 ||
		!exactStrings(mapAt(mappings, "all_access")["backend_roles"], "admin") ||
		!exactStrings(mapAt(mappings, "kibana_server")["users"], "kibanaserver") ||
		!exactStrings(mapAt(mappings, "fluentbit_writer")["backend_roles"], "fluentbit_writer") ||
		mappings["dashboard_server"] != nil ||
		mappings["security_rest_api_access"] != nil {
		return errors.New("OpenSearch role mapping is invalid")
	}
	roles, err := decodeInlineYAML(data["roles.yml"])
	if err != nil || len(roles) != 2 || roles["fluentbit_writer"] == nil {
		return errors.New("OpenSearch roles are not minimal")
	}
	writer := mapAt(roles, "fluentbit_writer")
	permissions, _ := writer["index_permissions"].([]any)
	if !exactStrings(writer["cluster_permissions"], "cluster_composite_ops") ||
		len(permissions) != 1 ||
		!exactStrings(
			permissions[0].(map[string]any)["index_patterns"], "kubernetes-*", "node-*",
		) ||
		!exactStrings(
			permissions[0].(map[string]any)["allowed_actions"], "create_index", "crud",
		) {
		return errors.New("OpenSearch Fluent Bit writer role exceeds its declared scope")
	}
	for _, key := range []string{"action_groups.yml", "tenants.yml"} {
		minimal, err := decodeInlineYAML(data[key])
		if err != nil || len(minimal) != 1 || minimal["_meta"] == nil {
			return fmt.Errorf("OpenSearch %s is not minimal", key)
		}
	}
	for _, name := range []string{
		"opensearch-admin-credentials", "opensearch-dashboards-credentials",
		"fluentbit-opensearch-credentials",
	} {
		if secretByName(documents, name)["immutable"] != true {
			return fmt.Errorf("install-time Secret %s is mutable", name)
		}
	}
	adminCredentials := mapAt(
		secretByName(documents, "opensearch-admin-credentials"), "stringData",
	)
	dashboardCredentials := mapAt(
		secretByName(documents, "opensearch-dashboards-credentials"), "stringData",
	)
	fluentCredentials := mapAt(
		secretByName(documents, "fluentbit-opensearch-credentials"), "stringData",
	)
	if len(adminCredentials) != 2 ||
		adminCredentials["username"] != "admin" ||
		adminCredentials["password"] != "${ATUM_STATEFUL_OPENSEARCH_ADMIN_PASSWORD}" ||
		len(dashboardCredentials) != 3 ||
		dashboardCredentials["username"] != "kibanaserver" ||
		dashboardCredentials["password"] !=
			"${ATUM_STATEFUL_OPENSEARCH_DASHBOARDS_PASSWORD}" ||
		dashboardCredentials["cookie"] !=
			"${ATUM_STATEFUL_OPENSEARCH_DASHBOARDS_COOKIE}" ||
		len(fluentCredentials) != 2 ||
		fluentCredentials["OPENSEARCH_USER"] != "fluentbit" ||
		fluentCredentials["OPENSEARCH_PASSWORD"] !=
			"${ATUM_STATEFUL_FLUENTBIT_OPENSEARCH_PASSWORD}" {
		return errors.New("OpenSearch credential projection does not match native identities")
	}
	for _, name := range []string{"opensearch-dashboards-ca", "fluentbit-opensearch-ca"} {
		secret := secretByName(documents, name)
		ca := mapAt(secret, "data")
		if secret["immutable"] != true || len(ca) != 1 ||
			ca["ca.crt"] != "${ATUM_ROOT_CA_CERTIFICATE_B64}" {
			return fmt.Errorf("consumer trust Secret %s is not CA-only and immutable", name)
		}
	}
	if len(certificates) != 1 {
		return errors.New("unused OpenSearch client certificate remains")
	}
	certificate := certificates[0]
	certificateSpec := mapAt(certificate, "spec")
	if mapAt(certificate, "metadata")["name"] != "opensearch-node" ||
		mapAt(certificate, "metadata")["namespace"] != "opensearch" ||
		certificateSpec["commonName"] != "opensearch-node" ||
		certificateSpec["secretName"] != "opensearch-node-tls" ||
		mapAt(certificateSpec, "issuerRef")["group"] != "cert-manager.io" ||
		mapAt(certificateSpec, "issuerRef")["kind"] != "ClusterIssuer" ||
		mapAt(certificateSpec, "issuerRef")["name"] != "atum-test-ca" ||
		!exactStrings(certificateSpec["dnsNames"],
			"opensearch-cluster-master",
			"opensearch-cluster-master.opensearch",
			"opensearch-cluster-master.opensearch.svc",
			"opensearch-cluster-master.opensearch.svc.cluster.local",
			"*.opensearch-cluster-master-headless",
			"*.opensearch-cluster-master-headless.opensearch",
			"*.opensearch-cluster-master-headless.opensearch.svc",
			"*.opensearch-cluster-master-headless.opensearch.svc.cluster.local",
		) ||
		!exactStrings(certificateSpec["usages"], "server auth", "client auth") {
		return errors.New("OpenSearch node certificate identity drifted")
	}

	dashboards := mapAt(operational, "packages", "opensearch-dashboards", "values")
	if dashboards["opensearchHosts"] !=
		"https://opensearch-cluster-master.opensearch.svc.cluster.local:9200" ||
		mapAt(dashboards, "opensearchAccount")["secret"] !=
			"opensearch-dashboards-credentials" {
		return errors.New("OpenSearch Dashboards endpoint or credential Secret drifted")
	}
	dashboardMounts, _ := dashboards["secretMounts"].([]any)
	if len(dashboardMounts) != 1 ||
		dashboardMounts[0].(map[string]any)["name"] != "opensearch-ca" ||
		dashboardMounts[0].(map[string]any)["secretName"] != "opensearch-dashboards-ca" ||
		dashboardMounts[0].(map[string]any)["path"] !=
			"/usr/share/opensearch-dashboards/config/certificates" ||
		dashboardMounts[0].(map[string]any)["subPath"] != nil {
		return errors.New("OpenSearch Dashboards trust mount drifted")
	}
	dashboardConfig, err := decodeInlineYAML(
		mapAt(dashboards, "config")["opensearch_dashboards.yml"],
	)
	if err != nil || len(dashboardConfig) != 2 ||
		!exactStrings(
			dashboardConfig["opensearch.ssl.certificateAuthorities"],
			"/usr/share/opensearch-dashboards/config/certificates/ca.crt",
		) ||
		dashboardConfig["opensearch.ssl.verificationMode"] != "full" {
		return errors.New("OpenSearch Dashboards server verification drifted")
	}

	fluentBit := mapAt(operational, "fluentbit", "values", "upstream")
	envFrom, _ := fluentBit["envFrom"].([]any)
	volumes, _ := fluentBit["extraVolumes"].([]any)
	volumeMounts, _ := fluentBit["extraVolumeMounts"].([]any)
	if len(envFrom) != 1 ||
		mapAt(envFrom[0].(map[string]any), "secretRef")["name"] !=
			"fluentbit-opensearch-credentials" ||
		len(volumes) != 2 ||
		volumes[0].(map[string]any)["name"] != "flb-storage" ||
		mapAt(volumes[0].(map[string]any), "hostPath")["path"] !=
			"/var/log/flb-storage/" ||
		mapAt(volumes[0].(map[string]any), "hostPath")["type"] !=
			"DirectoryOrCreate" ||
		volumes[1].(map[string]any)["name"] != "opensearch-ca" ||
		mapAt(volumes[1].(map[string]any), "secret")["secretName"] !=
			"fluentbit-opensearch-ca" ||
		len(volumeMounts) != 2 ||
		volumeMounts[0].(map[string]any)["name"] != "flb-storage" ||
		volumeMounts[0].(map[string]any)["mountPath"] !=
			"/var/log/flb-storage/" ||
		volumeMounts[0].(map[string]any)["readOnly"] != false ||
		volumeMounts[1].(map[string]any)["name"] != "opensearch-ca" ||
		volumeMounts[1].(map[string]any)["mountPath"] != "/fluent-bit/tls" ||
		volumeMounts[1].(map[string]any)["readOnly"] != true {
		return errors.New("Fluent Bit credential or CA projection drifted")
	}
	outputs, _ := mapAt(fluentBit, "config")["outputs"].(string)
	for line, count := range map[string]int{
		"Name                opensearch":                                             2,
		"Host                opensearch-cluster-master.opensearch.svc.cluster.local": 2,
		"Port                9200":                                                   2,
		"HTTP_User           ${OPENSEARCH_USER}":                                     2,
		"HTTP_Passwd         ${OPENSEARCH_PASSWORD}":                                 2,
		"tls                 On":                                                     2,
		"tls.verify          On":                                                     2,
		"tls.ca_file         /fluent-bit/tls/ca.crt":                                 2,
	} {
		if strings.Count(outputs, line) != count {
			return fmt.Errorf("Fluent Bit OpenSearch output line %q drifted", line)
		}
	}
	if strings.Contains(outputs, "$${OPENSEARCH_") {
		return errors.New("Fluent Bit runtime credential reference is escaped")
	}
	dependencies, _ := mapAt(access, "spec")["dependsOn"].([]any)
	substitutions, _ := mapAt(access, "spec", "postBuild")["substituteFrom"].([]any)
	if !namedReference(dependencies, "platform-certificates") ||
		!namedReference(substitutions, "atum-platform-stateful") ||
		!namedReference(substitutions, "atum-platform-root-ca-public") {
		return errors.New("Flux OpenSearch security dependency path is incomplete")
	}
	return nil
}

func exactStrings(value any, expected ...string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	for index, item := range items {
		if item != expected[index] {
			return false
		}
	}
	return true
}

func decodeInlineYAML(value any) (map[string]any, error) {
	text, ok := value.(string)
	if !ok {
		return nil, errors.New("inline YAML is not a string")
	}
	var decoded map[string]any
	if err := yaml.Unmarshal([]byte(text), &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func readPlatformValues(t *testing.T, path string) (string, map[string]any) {
	t.Helper()
	data := []byte(readPlatformText(t, path))
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return string(data), values
}

func readPlatformText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readPlatformDocuments(t *testing.T, path string) []map[string]any {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(readPlatformText(t, path)))
	var documents []map[string]any
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return documents
		}
		if err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if len(document) != 0 {
			documents = append(documents, document)
		}
	}
}

func secretByName(documents []map[string]any, name string) map[string]any {
	for _, document := range documents {
		if document["kind"] == "Secret" &&
			mapAt(document, "metadata")["name"] == name {
			return document
		}
	}
	return nil
}

func cloneDocuments(documents []map[string]any) []map[string]any {
	result := make([]map[string]any, len(documents))
	for index := range documents {
		result[index] = cloneMap(documents[index])
	}
	return result
}

func namedReference(references []any, name string) bool {
	for _, reference := range references {
		item, _ := reference.(map[string]any)
		if item["name"] == name {
			return true
		}
	}
	return false
}

func stringReference(references []any, name string) bool {
	for _, reference := range references {
		if reference == name {
			return true
		}
	}
	return false
}

func policyExcludesResource(
	values map[string]any, policy, namespace, name string,
) bool {
	exclusions := mapSlice(mapAt(
		values, "kyvernoPolicies", "values", "policies", policy, "exclude",
	)["any"])
	for _, exclusion := range exclusions {
		resources := mapAt(exclusion, "resources")
		namespaces, _ := resources["namespaces"].([]any)
		names, _ := resources["names"].([]any)
		if stringReference(namespaces, namespace) &&
			stringReference(names, name) {
			return true
		}
	}
	return false
}
