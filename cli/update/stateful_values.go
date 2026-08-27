package update

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"

	"atum/cli/config"

	"gopkg.in/yaml.v3"
)

const (
	statefulValuesTemplatePath    = "platform/templates/secrets/stateful-values.yaml.tmpl"
	statefulOpenSearchSecretsPath = "platform/profiles/local/access/opensearch-secrets.yaml"
)

type platformValuesSource struct {
	kind       string
	name       string
	valuesKey  string
	targetPath string
	optional   bool
}

var platformValuesSources = [...]platformValuesSource{
	{
		kind: "ConfigMap", name: "bigbang-operational-values", valuesKey: "values.yaml",
	},
	{
		kind: "ConfigMap", name: "bigbang-generated-values", valuesKey: "values.yaml",
	},
	{
		kind: "ConfigMap", name: "bigbang-target-values", valuesKey: "values.yaml",
	},
	{
		kind: "Secret", name: "atum-platform-stateful-values", valuesKey: "values.yaml",
	},
	{
		kind:       "Secret",
		name:       "atum-platform-stateful-values",
		valuesKey:  "garage-admin-token",
		targetPath: "packages.garage.values.garageInit.adminToken",
	},
	{
		kind:       "Secret",
		name:       "atum-platform-stateful-values",
		valuesKey:  "garage-admin-token",
		targetPath: "packages.garage.values.upstream.environment[0].value",
	},
	{
		kind:       "Secret",
		name:       "atum-platform-stateful-values",
		valuesKey:  "garage-access-key-id",
		targetPath: "packages.garage.values.garageInit.consumers[0].credentials.accessKeyId",
	},
	{
		kind:       "Secret",
		name:       "atum-platform-stateful-values",
		valuesKey:  "garage-secret-access-key",
		targetPath: "packages.garage.values.garageInit.consumers[0].credentials.secretAccessKey",
	},
	{
		kind: "Secret", name: "atum-platform-identity-values",
		valuesKey: "values.yaml", optional: true,
	},
	{
		kind: "Secret", name: "atum-sso-ca", valuesKey: "ca.crt",
		targetPath: "sso.certificateAuthority.cert", optional: true,
	},
}

type statefulValuesProjection struct {
	values       map[string]any
	targetValues map[string]string
}

var (
	statefulPlaceholderPattern = regexp.MustCompile(`\$\{(ATUM_STATEFUL_[A-Z0-9_]+)\}`)
	statefulRenderSentinels    = map[string]string{
		"ATUM_STATEFUL_POSTGRESQL_PASSWORD":                    "atum-render-only",
		"ATUM_STATEFUL_REDIS_PASSWORD":                         "atum-render-only",
		"ATUM_STATEFUL_GARAGE_ADMIN_TOKEN":                     "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GARAGE_ACCESS_KEY_ID":                   "GK000000000000000000000000",
		"ATUM_STATEFUL_GARAGE_SECRET_ACCESS_KEY":               "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GITLAB_SECRET_KEY_BASE":                 "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GITLAB_OTP_KEY_BASE":                    "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GITLAB_DB_KEY_BASE":                     "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GITLAB_ENCRYPTED_SETTINGS_KEY_BASE":     "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GITLAB_ACTIVE_RECORD_PRIMARY_KEY":       "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GITLAB_ACTIVE_RECORD_DETERMINISTIC_KEY": "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_GITLAB_ACTIVE_RECORD_SALT":              "0000000000000000000000000000000000000000000000000000000000000000",
		"ATUM_STATEFUL_OPENSEARCH_ADMIN_PASSWORD":              "atum-render-only-opensearch-admin",
		"ATUM_STATEFUL_OPENSEARCH_ADMIN_HASH":                  "$2y$10$......................../................................",
		"ATUM_STATEFUL_OPENSEARCH_DASHBOARDS_PASSWORD":         "atum-render-only-opensearch-dashboards",
		"ATUM_STATEFUL_OPENSEARCH_DASHBOARDS_HASH":             "$2y$10$......................../................................",
		"ATUM_STATEFUL_OPENSEARCH_DASHBOARDS_COOKIE":           "atum-render-only-opensearch-cookie",
		"ATUM_STATEFUL_FLUENTBIT_OPENSEARCH_PASSWORD":          "atum-render-only-fluentbit-opensearch",
		"ATUM_STATEFUL_FLUENTBIT_OPENSEARCH_HASH":              "$2y$10$......................../................................",
	}
)

// loadStatefulValuesOverlay validates only Atum's projection boundary. Package
// semantics remain owned by Big Bang and the selected charts.
func loadStatefulValuesOverlay(
	files map[string][]byte,
	desired config.Document,
) (statefulValuesProjection, error) {
	target, found := desired.ActiveTarget()
	if !found {
		return statefulValuesProjection{}, errors.New("active platform target is unavailable")
	}
	valuesPath, found := desired.Platform.Values.Profiles[target.PlatformProfile]
	if !found {
		return statefulValuesProjection{}, fmt.Errorf("platform profile %s has no values path", target.PlatformProfile)
	}
	outputPath := filepath.ToSlash(filepath.Join(filepath.Dir(valuesPath), "stateful-values.yaml"))
	_, found = files[outputPath]
	if !found {
		return statefulValuesProjection{}, fmt.Errorf("required stateful values output %s is not managed", outputPath)
	}
	template, found := files[statefulValuesTemplatePath]
	if !found {
		return statefulValuesProjection{}, fmt.Errorf("required stateful values template %s is not managed", statefulValuesTemplatePath)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(template))
	var projection statefulValuesProjection
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return statefulValuesProjection{}, fmt.Errorf("decode stateful values projection: %w", err)
		}
		if document["apiVersion"] != "v1" || document["kind"] != "Secret" {
			continue
		}
		metadata := mapAt(document, "metadata")
		if metadata["name"] != "atum-platform-stateful-values" ||
			metadata["namespace"] != "bigbang" {
			continue
		}
		stringData := mapAt(document, "stringData")
		content, _ := stringData["values.yaml"].(string)
		projection.values, err = decodeReleaseValues(content)
		if err != nil {
			return statefulValuesProjection{}, fmt.Errorf("decode projected Big Bang values: %w", err)
		}
		projection.targetValues = make(map[string]string, len(platformValuesSources))
		for _, target := range platformValuesSources {
			if !target.isStatefulTarget() {
				continue
			}
			if _, exists := projection.targetValues[target.valuesKey]; exists {
				continue
			}
			value, ok := stringData[target.valuesKey].(string)
			if !ok || value == "" {
				return statefulValuesProjection{}, fmt.Errorf(
					"stateful values projection is missing scalar key %s",
					target.valuesKey,
				)
			}
			projection.targetValues[target.valuesKey] = value
		}
	}
	if projection.values == nil {
		return statefulValuesProjection{}, errors.New("stateful values projection has no Big Bang values Secret")
	}
	observed := make(map[string]struct{}, len(statefulRenderSentinels))
	collectStatefulPlaceholders(projection.values, observed)
	for _, value := range projection.targetValues {
		collectStatefulPlaceholders(value, observed)
	}
	openSearchSecrets, found := files[statefulOpenSearchSecretsPath]
	if !found {
		return statefulValuesProjection{}, fmt.Errorf(
			"required OpenSearch Secret projection %s is not managed",
			statefulOpenSearchSecretsPath,
		)
	}
	for _, match := range statefulPlaceholderPattern.FindAllSubmatch(openSearchSecrets, -1) {
		observed[string(match[1])] = struct{}{}
	}
	for name := range observed {
		if _, allowed := statefulRenderSentinels[name]; !allowed {
			return statefulValuesProjection{}, fmt.Errorf(
				"stateful values projection uses unknown placeholder %s",
				name,
			)
		}
	}
	for name := range statefulRenderSentinels {
		if _, found := observed[name]; !found {
			return statefulValuesProjection{}, fmt.Errorf("stateful values projection is missing %s", name)
		}
	}
	return projection, nil
}

// renderStatefulValuesOverlay models the native Flux targetPath merges used by
// the Big Bang HelmRelease. The persisted secret layer carries only scalar
// Garage credentials; the one operational consumer list remains the
// authoritative bucket topology.
func renderStatefulValuesOverlay(
	projection statefulValuesProjection,
	operational map[string]any,
) (map[string]any, error) {
	garageInit := mapAt(operational, "packages", "garage", "values", "garageInit")
	upstream := mapAt(operational, "packages", "garage", "values", "upstream")

	values := statefulRenderValues(projection.values)
	mergeMaps(values, map[string]any{
		"packages": map[string]any{
			"garage": map[string]any{
				"values": map[string]any{
					"garageInit": cloneMap(garageInit),
					"upstream": map[string]any{
						"environment": cloneValue(upstream["environment"]),
					},
				},
			},
		},
	})
	for _, target := range platformValuesSources {
		if !target.isStatefulTarget() {
			continue
		}
		value := statefulRenderText(projection.targetValues[target.valuesKey])
		if err := setReleaseTarget(values, target.targetPath, value, false); err != nil {
			return nil, fmt.Errorf("apply stateful values target %s: %w", target.targetPath, err)
		}
	}
	return values, nil
}

// statefulRenderValues substitutes non-secret schema-valid sentinels in
// memory. Helm validates selected package values before Flux substitutes the
// bootstrap Secret; the updater must therefore observe a renderable values
// shape without persisting or logging credentials.
func statefulRenderValues(values map[string]any) map[string]any {
	renderValues := cloneMap(values)
	substituteStatefulRenderValues(renderValues)
	return renderValues
}

func substituteStatefulRenderValues(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				typed[key] = statefulRenderText(text)
				continue
			}
			substituteStatefulRenderValues(child)
		}
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok {
				typed[index] = statefulRenderText(text)
				continue
			}
			substituteStatefulRenderValues(child)
		}
	}
}

func statefulRenderText(value string) string {
	return statefulPlaceholderPattern.ReplaceAllStringFunc(
		value,
		func(placeholder string) string {
			matches := statefulPlaceholderPattern.FindStringSubmatch(placeholder)
			if sentinel, found := statefulRenderSentinels[matches[1]]; found {
				return sentinel
			}
			return placeholder
		},
	)
}

func (source platformValuesSource) isStatefulTarget() bool {
	return source.kind == "Secret" &&
		source.name == "atum-platform-stateful-values" &&
		source.targetPath != ""
}

func (source platformValuesSource) fluxValue() map[string]any {
	value := map[string]any{
		"kind": source.kind, "name": source.name, "valuesKey": source.valuesKey,
	}
	if source.targetPath != "" {
		value["targetPath"] = source.targetPath
	}
	if source.optional {
		value["optional"] = true
	}
	return value
}

func matchesPlatformValuesSource(raw any, expected platformValuesSource) bool {
	value, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	actualKind, _ := value["kind"].(string)
	actualName, _ := value["name"].(string)
	actualKey, _ := value["valuesKey"].(string)
	actualTarget, targetFound := value["targetPath"].(string)
	actualOptional, optionalFound := value["optional"].(bool)
	expectedLength := 3
	if expected.optional {
		expectedLength++
	}
	if expected.targetPath != "" {
		expectedLength++
	}
	return len(value) == expectedLength &&
		actualKind == expected.kind &&
		actualName == expected.name &&
		actualKey == expected.valuesKey &&
		targetFound == (expected.targetPath != "") &&
		actualTarget == expected.targetPath &&
		optionalFound == expected.optional &&
		actualOptional == expected.optional
}

func collectStatefulPlaceholders(value any, observed map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			collectStatefulPlaceholders(child, observed)
		}
	case []any:
		for _, child := range typed {
			collectStatefulPlaceholders(child, observed)
		}
	case string:
		for _, match := range statefulPlaceholderPattern.FindAllStringSubmatch(typed, -1) {
			observed[match[1]] = struct{}{}
		}
	}
}

// validateNoConfiguredStatefulCredentials keeps plaintext out of updater
// inputs. The final values Secret is the sole credential projection.
func validateNoConfiguredStatefulCredentials(layers ...map[string]any) error {
	paths := [][]string{
		{"addons", "gitlab", "database", "password"},
		{"addons", "gitlab", "redis", "password"},
		{"addons", "gitlab", "objectStorage", "accessKey"},
		{"addons", "gitlab", "objectStorage", "accessSecret"},
		{"addons", "gitlab", "railsSecret"},
		{"packages", "redis", "values", "upstream", "auth", "password"},
		{"packages", "garage", "values", "garageInit", "adminToken"},
	}
	for _, values := range layers {
		for _, path := range paths {
			if stringAt(values, path...) != "" {
				return fmt.Errorf("operational or generated values contain credential material at %v", path)
			}
		}
		consumers := mapSlice(
			mapAt(values, "packages", "garage", "values", "garageInit")["consumers"],
		)
		for _, consumer := range consumers {
			credentials := mapAt(consumer, "credentials")
			if stringAt(credentials, "accessKeyId") != "" ||
				stringAt(credentials, "secretAccessKey") != "" {
				return errors.New("operational or generated values contain Garage credentials")
			}
		}
		environment := mapSlice(
			mapAt(values, "packages", "garage", "values", "upstream")["environment"],
		)
		for _, variable := range environment {
			if stringAt(variable, "name") == "GARAGE_ADMIN_TOKEN" &&
				stringAt(variable, "value") != "" {
				return errors.New("operational or generated values contain a Garage administration token")
			}
		}
	}
	return nil
}
