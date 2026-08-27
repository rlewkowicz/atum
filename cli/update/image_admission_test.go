package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
	"testing"

	"atum/cli/config"
)

func TestFinalRenderConfigMapPathsDriveCompatibility(t *testing.T) {
	t.Parallel()
	manifest := []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana
  namespace: monitoring
data:
  grafana.ini: |
    [plugin.example]
    path = /var/lib/bb-plugins/example
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
spec:
  template:
    spec:
      containers:
        - name: grafana
          image: registry.atum.test/atum/grafana:13.0.1
          volumeMounts:
            - name: config
              mountPath: /etc/grafana/grafana.ini
              subPath: grafana.ini
      volumes:
        - name: config
          configMap:
            name: grafana
`)
	inspection, err := inspectManifestData("grafana.yaml", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Invocations) != 1 {
		t.Fatalf("got %d invocations, want 1", len(inspection.Invocations))
	}
	paths := mustRequiredInvocationPaths(t, inspection.Invocations[0])
	if !containsString(paths, "/var/lib/bb-plugins/example") {
		t.Fatalf("mounted final configuration path is absent: %#v", paths)
	}
	if containsString(paths, "/etc/grafana/grafana.ini") {
		t.Fatalf("mounted file was treated as an image obligation: %#v", paths)
	}
}

func TestFinalRenderConfigurationDoesNotInventRuntimePathObligations(t *testing.T) {
	t.Parallel()
	var paths []string
	collectConfigurationImagePaths(`
client_path: /home/application/client/bin
socket_path: /run/application/socket
data_dir: /var/lib/application
pid_file: /run/application.pid
static.path = /srv/application/assets
`, &paths)
	paths = compactSorted(paths)
	if !containsString(paths, "/srv/application/assets") {
		t.Fatalf("explicit static asset path is absent: %#v", paths)
	}
	for _, runtimePath := range []string{
		"/home/application/client/bin",
		"/run/application/socket",
		"/var/lib/application",
		"/run/application.pid",
	} {
		if containsString(paths, runtimePath) {
			t.Fatalf("runtime configuration %q became an image obligation: %#v", runtimePath, paths)
		}
	}
}

func TestMountedShellConfigurationDoesNotInventImagePaths(t *testing.T) {
	t.Parallel()
	invocation := containerInvocation{
		Command: []any{
			"sh",
			"-ec",
			`sed 's|^storage:|storage: /var/opt/gitlab/repo|' /mounted/config > /mounted/output`,
		},
		MountedFiles: []mountedConfigFile{
			mountedConfigFileForTest(
				"/mounted/config",
				"custom.path = /home/git/custom_hooks\n"+
					"route.path = /metrics\n"+
					"pattern.path = /^storage:\n",
			),
		},
		Runtime: map[string]any{
			"volumeMounts": []any{
				map[string]any{"name": "config", "mountPath": "/mounted"},
			},
		},
	}
	obligations, err := requiredInvocationObligations(invocation, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	paths := obligationPaths(obligations)
	for _, falsePath := range []string{"/metrics", "/^storage:"} {
		if containsString(paths, falsePath) {
			t.Fatalf("shell configuration path %q was treated as an image obligation: %#v", falsePath, paths)
		}
	}
	for _, executable := range []string{"sh", "sed"} {
		found := false
		for _, obligation := range obligations {
			found = found || (obligation.Path == executable &&
				obligation.Executable && obligation.SearchPATH)
		}
		if !found {
			t.Fatalf("shell executable %q evidence is absent: %#v", executable, obligations)
		}
	}
	for _, configured := range []string{"/metrics", "/^storage:"} {
		if configurationImagePath(configured) {
			t.Fatalf("configuration route or expression %q was treated as an image path", configured)
		}
	}
}

func TestMountedScriptExistenceGuardDoesNotRequireOptionalPath(t *testing.T) {
	t.Parallel()

	const optionalPath = "/etc/secrets/postgresql/..data"
	invocation := containerInvocation{
		Command: []any{"/bin/sh", "/scripts/runcheck"},
		MountedFiles: []mountedConfigFile{mountedConfigFileForTest(
			"/scripts/runcheck",
			`#!/bin/sh
secrets_dir="/etc/secrets/postgresql"
if [ -d "${secrets_dir}" ]; then
  if [ ! "$(ls -A ${secrets_dir}/..data/)" = "" ]; then
    echo "mounted secret is populated"
  fi
fi
`,
		)},
		Runtime: map[string]any{
			"volumeMounts": []any{
				map[string]any{"name": "scripts", "mountPath": "/scripts"},
			},
		},
	}
	obligations, err := requiredInvocationObligations(invocation, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	paths := obligationPaths(obligations)
	if containsString(paths, optionalPath) {
		t.Fatalf("existence-guarded runtime path became an image obligation: %#v", paths)
	}
	foundLS := false
	for _, obligation := range obligations {
		foundLS = foundLS || obligation.Path == "ls" && obligation.SearchPATH
	}
	if !foundLS {
		t.Fatalf("guarded command executable is absent: %#v", obligations)
	}

	invocation.MountedFiles[0] = mountedConfigFileForTest(
		"/scripts/runcheck",
		"#!/bin/sh\nls -A "+optionalPath+"\n",
	)
	paths = mustRequiredInvocationPaths(t, invocation)
	if !containsString(paths, optionalPath) {
		t.Fatalf("unguarded path was not retained as an image obligation: %#v", paths)
	}
}

func TestCompatibilityComparisonUsesConcreteFinalPaths(t *testing.T) {
	t.Parallel()
	image := config.Image{
		ID: "grafana-plugins",
		BigBangRefs: []string{
			"registry1.dso.mil/ironbank/big-bang/grafana/grafana-plugins:13.0.1",
		},
	}
	use := finalImageUse{
		artifact:      "package/grafana",
		requiredPaths: []string{"/var/lib/bb-plugins/example"},
		invocation: containerInvocation{
			Location: "deployment/grafana",
		},
	}
	compatible := officialImageInspection{
		pathExists: map[string]bool{"/var/lib/bb-plugins/example": true},
	}
	if mismatches := compareOfficialCandidate(image, compatible, []finalImageUse{use}); len(mismatches) != 0 {
		t.Fatalf("compatible official image rejected: %#v", mismatches)
	}
	incompatible := officialImageInspection{pathExists: map[string]bool{}}
	mismatches := compareOfficialCandidate(image, incompatible, []finalImageUse{use})
	if len(mismatches) != 1 ||
		!strings.Contains(mismatches[0], "official path /var/lib/bb-plugins/example") {
		t.Fatalf("concrete mismatch was not attributed: %#v", mismatches)
	}
}

func TestDirectSearchChartIncompatibilityCannotCreateCompatibilityBuild(t *testing.T) {
	t.Parallel()

	const obligation = "rendered lifecycle hook"
	for _, imageID := range []string{"opensearch", "opensearch-dashboards"} {
		imageID := imageID
		t.Run(imageID, func(t *testing.T) {
			t.Parallel()

			artifact := "chart/" + imageID
			location := "statefulset/" + imageID + "/container/" + imageID
			image := config.Image{ID: imageID, Version: "3.8.0"}
			use := finalImageUse{
				artifact: artifact,
				invocation: containerInvocation{
					Location: location,
				},
				obligations: []filesystemObligation{{
					Path:       "curl",
					Origin:     obligation,
					Executable: true,
				}},
			}
			mismatches := compareOfficialCandidate(
				image,
				officialImageInspection{pathExists: map[string]bool{}},
				[]finalImageUse{use},
			)
			if len(mismatches) != 1 {
				t.Fatalf("mismatches = %#v", mismatches)
			}
			controlTarget, controlMaterials, controlErr := compatibilityBuildRecipe(
				config.Image{ID: "vault"},
				"",
				mismatches,
			)
			if controlErr != nil ||
				controlTarget != "vault-curl-compat" ||
				len(controlMaterials) == 0 {
				t.Fatalf(
					"fixture does not match a generic compatibility recipe: target=%q materials=%#v err=%v",
					controlTarget,
					controlMaterials,
					controlErr,
				)
			}
			target, materials, recipeErr := compatibilityBuildRecipe(
				image,
				"",
				mismatches,
			)
			if recipeErr == nil || target != "" || len(materials) != 0 {
				t.Fatalf(
					"direct search mismatch authorized a build: target=%q materials=%#v err=%v",
					target,
					materials,
					recipeErr,
				)
			}
			admissionErr := officialCandidateCompatibilityError(
				"",
				image.ID,
				mismatches,
				recipeErr,
			)
			for _, evidence := range []string{
				imageID,
				artifact,
				location,
				obligation,
				"curl",
				"requires an official immutable mirror",
				"compatibility builds are forbidden",
			} {
				if !strings.Contains(admissionErr.Error(), evidence) {
					t.Errorf("admission error lacks %q: %v", evidence, admissionErr)
				}
			}
		})
	}
}

func TestDirectSearchChartCachedIncompatibilityUsesClosedRecipeBoundary(t *testing.T) {
	t.Parallel()

	mismatches := []string{
		"chart/opensearch/statefulset/opensearch: rendered lifecycle hook requires official executable curl",
	}
	target, materials, err := compatibilityBuildRecipe(
		config.Image{ID: "opensearch"},
		"",
		mismatches,
	)
	if err == nil || target != "" || len(materials) != 0 {
		t.Fatalf(
			"cached direct search evidence authorized a build: target=%q materials=%#v err=%v",
			target,
			materials,
			err,
		)
	}
	if !strings.Contains(err.Error(), "compatibility builds are forbidden") {
		t.Fatalf("cached recipe error lacks no-build reason: %v", err)
	}
}

func TestInactiveHelmTestHookDoesNotAdmitImage(t *testing.T) {
	t.Parallel()
	inspection, err := inspectManifestData("test.yaml", []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: package-test
  annotations:
    helm.sh/hook: test-success
spec:
  containers:
    - name: test
      image: alpine:3.17
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Images) != 0 || len(inspection.Invocations) != 0 {
		t.Fatalf("inactive Helm test admitted runtime state: %#v", inspection)
	}
}

func TestProductionHelmLifecycleHookAdmitsImage(t *testing.T) {
	t.Parallel()
	inspection, err := inspectManifestData("pre-delete.yaml", []byte(`
apiVersion: batch/v1
kind: Job
metadata:
  name: cleanup
  annotations:
    helm.sh/hook: pre-delete
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: cleanup
          image: example.com/readiness-checker:v1.2.3
          args:
            - scale-deploy
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Images) != 1 ||
		inspection.Images[0] != "example.com/readiness-checker:v1.2.3" ||
		len(inspection.Invocations) != 1 {
		t.Fatalf("production lifecycle hook was not admitted: %#v", inspection)
	}
}

func TestRegistry1CandidateInspectionFailsBeforeTransport(t *testing.T) {
	t.Parallel()
	_, err := inspectOfficialImage(
		context.Background(),
		"registry1.dso.mil/ironbank/opensource/postgres/postgresql:18.4",
		nil,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "Registry1 candidates are forbidden") {
		t.Fatalf("Registry1 inspection error = %v", err)
	}
}

func TestEntrypointEnvironmentRequiresFinalObservationAndOfficialSupport(t *testing.T) {
	t.Parallel()
	image := config.Image{
		ID: "postgresql-18",
		BigBangRefs: []string{
			"registry1.dso.mil/ironbank/opensource/postgres/postgresql:18.4",
		},
	}
	use := finalImageUse{
		artifact: "package/keycloak",
		invocation: containerInvocation{
			Location: "statefulset/postgresql",
			Runtime: map[string]any{
				"env": []any{
					map[string]any{
						"name":  "POSTGRESQL_VOLUME_DIR",
						"value": "/var/lib/postgresql",
					},
				},
				"volumeMounts": []any{
					map[string]any{
						"name":      "data",
						"mountPath": "/var/lib/postgresql",
					},
				},
			},
		},
	}
	required := requiredEntrypointEnvironment(image, use.invocation)
	if len(required) != 1 || required[0] != "POSTGRESQL_VOLUME_DIR" {
		t.Fatalf("required entrypoint environment = %#v", required)
	}
	mismatches := compareOfficialCandidate(
		image,
		officialImageInspection{entrypointEnvironment: map[string]bool{}},
		[]finalImageUse{use},
	)
	if len(mismatches) != 1 ||
		!strings.Contains(mismatches[0], "POSTGRESQL_VOLUME_DIR") {
		t.Fatalf("missing official entrypoint support was not attributed: %#v", mismatches)
	}
	compatible := officialImageInspection{
		entrypointEnvironment: map[string]bool{"POSTGRESQL_VOLUME_DIR": true},
	}
	if mismatches := compareOfficialCandidate(image, compatible, []finalImageUse{use}); len(mismatches) != 0 {
		t.Fatalf("official entrypoint support was rejected: %#v", mismatches)
	}
}

func TestDirectOfficialImageRequiresVerifiedProvenance(t *testing.T) {
	t.Parallel()
	if _, err := directOfficialImage("example.invalid/unverified/image", "1.0.0"); err == nil {
		t.Fatal("unverified non-Registry1 image was classified as official")
	}
	spec, err := directOfficialImage("ghcr.io/cloudnative-pg/postgresql", "17.5")
	if err != nil {
		t.Fatal(err)
	}
	if spec.source != "ghcr.io/cloudnative-pg/postgresql:17.5" ||
		spec.provenance != "https://github.com/cloudnative-pg/postgres-containers" {
		t.Fatalf("CloudNativePG official provenance = %#v", spec)
	}
}

func TestConfiguredImageRequiresExactOfficialIdentity(t *testing.T) {
	t.Parallel()
	image := config.Image{
		ID:      "buildkit",
		License: "Apache-2.0",
		Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
			Type:   "mirror",
			Source: "docker.io/moby/buildkit:v0.25.2",
		}},
	}
	identity, err := configuredImageIdentity(image)
	if err != nil {
		t.Fatal(err)
	}
	if identity.provenance != "https://github.com/moby/buildkit" {
		t.Fatalf("configured provenance = %q", identity.provenance)
	}
	image.Delivery.Default.Source = "example.invalid/unverified/buildkit:v0.25.2"
	if _, err := configuredImageIdentity(image); err == nil {
		t.Fatal("unverified configured image was admitted")
	}
	image.Delivery.Default.Source = "registry1.dso.mil/ironbank/moby/buildkit:v0.25.2"
	if _, err := configuredImageIdentity(image); err == nil ||
		!strings.Contains(err.Error(), "forbidden Registry1") {
		t.Fatalf("Registry1 configured image error = %v", err)
	}
}

func TestRuntimeProvidedAndMountedPathsAreExcluded(t *testing.T) {
	t.Parallel()
	invocation := containerInvocation{
		Command: []any{"/bin/bash"},
		Args:    []any{"-ec", "touch /dev/null; cat /mounted/config"},
		Runtime: map[string]any{
			"volumeMounts": []any{
				map[string]any{"name": "config", "mountPath": "/mounted"},
			},
		},
	}
	paths := mustRequiredInvocationPaths(t, invocation)
	if containsString(paths, "/dev/null") || containsString(paths, "/mounted/config") {
		t.Fatalf("runtime-provided path was retained: %#v", paths)
	}
	if !containsString(paths, "/bin/bash") {
		t.Fatalf("rendered executable was omitted: %#v", paths)
	}
}

func TestArgumentRoutesDoNotBecomeFilesystemObligations(t *testing.T) {
	t.Parallel()
	invocation := containerInvocation{
		Args: []any{
			"--authorization-always-allow-paths=/metrics",
			"--health-endpoint=/healthz",
			"--tls-cert-file=/etc/application/tls.crt",
		},
	}
	paths := mustRequiredInvocationPaths(t, invocation)
	for _, route := range []string{"/metrics", "/healthz"} {
		if containsString(paths, route) {
			t.Fatalf("HTTP route %q was treated as an image obligation: %#v", route, paths)
		}
	}
	if !containsString(paths, "/etc/application/tls.crt") {
		t.Fatalf("concrete argument path is absent: %#v", paths)
	}
}

func TestExecutableQueriesPreserveExactPathsAndUseCandidatePATH(t *testing.T) {
	t.Parallel()
	queries := obligationQueryPaths([]filesystemObligation{
		{Path: "/bin/sh", Executable: true},
		{Path: "sed", Executable: true, SearchPATH: true},
		{Path: "/srv/application/assets"},
	}, []string{"PATH=/vendor/bin:/usr/bin"})
	for _, expected := range []string{
		"/bin/sh", "/vendor/bin/sed", "/usr/bin/sed", "/srv/application/assets",
	} {
		if !containsString(queries, expected) {
			t.Fatalf("exact query %q is absent: %#v", expected, queries)
		}
	}
	for _, forbidden := range []string{"/usr/bin/sh", "/bin/sed"} {
		if containsString(queries, forbidden) {
			t.Fatalf("unproven executable alternative %q is present: %#v", forbidden, queries)
		}
	}
}

func TestShellExecutablesRespectQuotedSeparatorsAndBuiltins(t *testing.T) {
	t.Parallel()
	executables, err := shellExecutables(`
cp /vault/config.hcl /tmp/storageconfig.hcl;
[ -n "${HOST_IP}" ] && sed -Ei "s|HOST_IP|${HOST_IP?}|g" /tmp/storageconfig.hcl;
if grep -vE '^[[:space:]]*(#|//)' /tmp/storageconfig.hcl | grep -qE 'placeholder'; then
  echo "invalid configuration";
  exit 1;
fi;
exec /usr/local/bin/docker-entrypoint.sh vault server
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"cp", "grep", "sed", "/usr/local/bin/docker-entrypoint.sh",
	} {
		if !containsString(executables, expected) {
			t.Fatalf("shell executable %q is absent: %#v", expected, executables)
		}
	}
	for _, invented := range []string{"HOST_IP", "g", "echo", "exec", "exit"} {
		if containsString(executables, invented) {
			t.Fatalf("shell token %q was treated as an executable: %#v", invented, executables)
		}
	}
}

func TestShellExecutablesResolveFunctionsAndCommandSubstitutions(t *testing.T) {
	t.Parallel()
	executables, err := shellExecutables(`
admin() {
  local method="$1" path="$2"; shift 2
  local args=(-sf -X "${method}" -H "Authorization: Bearer ${TOKEN}")
  curl "${args[@]}" "$@"
}
wait_start=$(date +%s)
status_json=$(admin GET v2/GetClusterStatus || echo '{}')
node_count=$(echo "${status_json}" | jq -r '(.nodes // []) | length')
for i in $(seq 0 3); do
  sleep 1
done
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"curl", "date", "jq", "seq", "sleep"} {
		if !containsString(executables, expected) {
			t.Fatalf("shell executable %q is absent: %#v", expected, executables)
		}
	}
	for _, invented := range []string{
		"+%s", "Authorization:", "GET", "admin", "i",
	} {
		if containsString(executables, invented) {
			t.Fatalf("shell token %q was treated as an executable: %#v", invented, executables)
		}
	}
}

func TestMountedScriptInterpreterPreservesShellDialect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		content     string
		path        string
		searchPath  bool
		interpreter string
	}{
		{
			name:        "bash syntax behind sh shebang",
			content:     "#!/bin/sh\nitems=(one two)\n[[ ${#items[@]} -gt 0 ]]\n",
			path:        "/bin/sh",
			interpreter: "bash",
		},
		{
			name:    "portable sh",
			content: "#!/bin/sh\nfor item in one two; do echo \"$item\"; done\n",
			path:    "/bin/sh",
		},
		{
			name:        "env bash",
			content:     "#!/usr/bin/env bash\nitems=(one two)\n",
			path:        "bash",
			searchPath:  true,
			interpreter: "bash",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			obligation, found := mountedScriptInterpreter(
				[]byte(test.content),
				"test",
			)
			if !found {
				t.Fatal("mounted script interpreter was not found")
			}
			if obligation.Path != test.path ||
				obligation.SearchPATH != test.searchPath ||
				obligation.Interpreter != test.interpreter ||
				!obligation.Executable {
				t.Fatalf("unexpected interpreter obligation: %#v", obligation)
			}
		})
	}
}

func TestReusableMirrorDigestRequiresAnIdenticalCandidate(t *testing.T) {
	t.Parallel()
	previous := config.Image{
		ID:          "controller",
		Family:      "controller",
		Version:     "1.2.3",
		Target:      "registry.atum.test/atum/controller:1.2.3",
		Consumers:   []string{"package/controller"},
		BigBangRefs: []string{"registry1.dso.mil/controller:1.2.3"},
		Discovery:   "rendered",
		Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
			Type:   "mirror",
			Source: "ghcr.io/example/controller:1.2.3",
			Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
	}
	candidate := previous
	candidate.Delivery.Default.Digest = ""
	digest, reusable := reusableMirrorDigest(candidate, previous)
	if !reusable || digest != previous.Delivery.Default.Digest {
		t.Fatalf("identical candidate digest = %q, reusable = %t", digest, reusable)
	}
	candidate.Version = "1.2.4"
	if digest, reusable := reusableMirrorDigest(candidate, previous); reusable || digest != "" {
		t.Fatalf("changed candidate digest = %q, reusable = %t", digest, reusable)
	}
}

func TestCompatibilityObservationsRequireAOneToOneJoin(t *testing.T) {
	t.Parallel()
	uses := []finalImageUse{
		{
			artifact: "package/controller",
			invocation: containerInvocation{
				Location:              "deployment/controller",
				RuntimeContractSHA256: "aaaaaaaa",
			},
		},
		{
			artifact: "package/helper",
			invocation: containerInvocation{
				Location:              "job/helper",
				RuntimeContractSHA256: "bbbbbbbb",
			},
		},
	}
	observations := []config.ImageRuntimeEvidence{
		{
			Artifact:              "package/controller",
			RenderedLocation:      "deployment/controller",
			RuntimeContractSHA256: "aaaaaaaa",
		},
		{
			Artifact:              "package/helper",
			RenderedLocation:      "job/helper",
			RuntimeContractSHA256: "bbbbbbbb",
		},
	}
	if !compatibilityObservationsMatch(uses, observations) {
		t.Fatal("one-to-one observations were rejected")
	}
	uses[1] = uses[0]
	if compatibilityObservationsMatch(uses, observations) {
		t.Fatal("duplicate runtime use reused one observation")
	}
}

func TestCompatibilityRemovalConditionBindsOfficialAndRenderedEvidence(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 64)
	observations := []config.ImageRuntimeEvidence{{
		Artifact:              "package/vault",
		RenderedLocation:      "statefulset/vault/init/prepare",
		RuntimeContractSHA256: digest,
	}}
	condition, err := compatibilityRemovalCondition(
		"docker.io/hashicorp/vault:1.21.4",
		[]string{
			"package/vault/statefulset/vault requires official executable curl",
			"package/vault/statefulset/vault requires official path /bin/sh",
		},
		observations,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range []string{
		"docker.io/hashicorp/vault",
		"docker.io/hashicorp/vault:1.21.4",
		"official executable curl",
		"official path /bin/sh",
		"package/vault/statefulset/vault/init/prepare@" + digest,
	} {
		if !strings.Contains(condition, evidence) {
			t.Errorf("removal condition lacks %q: %s", evidence, condition)
		}
	}
}

func TestCompatibleOfficialImageRemovesCompatibilityBuild(t *testing.T) {
	t.Parallel()
	source := "docker.io/hashicorp/vault:1.21.5"
	image := config.Image{
		ID: "vault",
		Compatibility: &config.ImageCompatibility{
			RemovalCondition: "stale compatibility evidence",
		},
		Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
			Type:       "build",
			Source:     source,
			BakeTarget: "vault-curl-compat",
			Materials:  []string{"stale material"},
		}},
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	if err := applyCompatibleOfficialMirror(
		&image,
		"index.docker.io/hashicorp/vault@"+digest,
	); err != nil {
		t.Fatal(err)
	}
	if image.Compatibility != nil {
		t.Fatalf("compatible mirror retained build evidence: %#v", image.Compatibility)
	}
	choice := image.Delivery.Default
	if choice.Type != "mirror" ||
		choice.Source != source ||
		choice.Digest != digest ||
		choice.BakeTarget != "" ||
		len(choice.Materials) != 0 {
		t.Fatalf("compatible delivery still contains build state: %#v", choice)
	}
}

func TestReusableCompatibilityRequiresCurrentSourceAndRemovalCondition(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("b", 64)
	source := "docker.io/hashicorp/vault:1.21.4"
	uses := []finalImageUse{{
		artifact: "package/vault",
		invocation: containerInvocation{
			Location:              "statefulset/vault/init/prepare",
			RuntimeContractSHA256: digest,
		},
	}}
	observations := []config.ImageRuntimeEvidence{{
		Artifact:              uses[0].artifact,
		RenderedLocation:      uses[0].invocation.Location,
		RuntimeContractSHA256: digest,
	}}
	mismatches := []string{
		"package/vault/statefulset/vault requires official executable curl",
	}
	condition, err := compatibilityRemovalCondition(
		source,
		mismatches,
		observations,
	)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &config.ImageCompatibility{
		Contract:         config.ImageAdmissionContract,
		Observations:     observations,
		Incompatibility:  strings.Join(mismatches, "; "),
		OfficialSource:   source,
		OfficialMaterial: "index.docker.io/hashicorp/vault@sha256:" + strings.Repeat("c", 64),
		RemovalCondition: condition,
	}
	candidate := config.Image{
		ID:         "vault",
		License:    "MPL-2.0",
		Provenance: "https://github.com/hashicorp/vault",
		Delivery: config.ImageDelivery{Default: config.DeliveryChoice{
			Type:   "mirror",
			Source: source,
		}},
	}
	receipt := candidate
	applyCompatibilityIdentity(&receipt, "vault-curl-compat")
	receipt.Delivery.Default = config.DeliveryChoice{
		Type:       "build",
		BakeTarget: "vault-curl-compat",
		Materials:  []string{evidence.OfficialMaterial},
	}
	receipt.Compatibility = evidence
	receipts := map[string]config.Image{candidate.ID: receipt}
	reused, err := reusableCompatibilityReceipt(
		config.DeliveryPolicy{},
		candidate,
		uses,
		receipts,
	)
	if err != nil || reused == nil {
		t.Fatalf("current compatibility evidence was not reused: evidence=%#v err=%v", reused, err)
	}
	withoutCondition := *evidence
	withoutCondition.RemovalCondition = ""
	receipt.Compatibility = &withoutCondition
	reused, err = reusableCompatibilityReceipt(
		config.DeliveryPolicy{},
		candidate,
		uses,
		map[string]config.Image{candidate.ID: receipt},
	)
	if err != nil || reused != nil {
		t.Fatalf("evidence without a removal condition was reused: evidence=%#v err=%v", reused, err)
	}
	changedSource := candidate
	changedSource.Delivery.Default.Source =
		"docker.io/hashicorp/vault:1.21.5"
	reused, err = reusableCompatibilityReceipt(
		config.DeliveryPolicy{},
		changedSource,
		uses,
		receipts,
	)
	if err != nil || reused != nil {
		t.Fatalf("evidence from a different official source was reused: evidence=%#v err=%v", reused, err)
	}
	changedLocation := append([]finalImageUse(nil), uses...)
	changedLocation[0].invocation.Location = "statefulset/vault/init/replaced"
	reused, err = reusableCompatibilityReceipt(
		config.DeliveryPolicy{},
		candidate,
		changedLocation,
		receipts,
	)
	if err != nil || reused != nil {
		t.Fatalf("evidence from a different rendered location was reused: evidence=%#v err=%v", reused, err)
	}
	changedArtifact := append([]finalImageUse(nil), uses...)
	changedArtifact[0].artifact = "package/vault-replacement"
	reused, err = reusableCompatibilityReceipt(
		config.DeliveryPolicy{},
		candidate,
		changedArtifact,
		receipts,
	)
	if err != nil || reused != nil {
		t.Fatalf("evidence from a different rendered artifact was reused: evidence=%#v err=%v", reused, err)
	}
	changedContract := append([]finalImageUse(nil), uses...)
	changedContract[0].invocation.RuntimeContractSHA256 = strings.Repeat("e", 64)
	reused, err = reusableCompatibilityReceipt(
		config.DeliveryPolicy{},
		candidate,
		changedContract,
		receipts,
	)
	if err != nil || reused != nil {
		t.Fatalf("evidence from a different runtime contract was reused: evidence=%#v err=%v", reused, err)
	}
}

func TestOfficialPathIndexRemovesOnlyTheAffectedSubtree(t *testing.T) {
	t.Parallel()
	index := newOfficialPathIndex(5)
	for _, name := range []string{
		"usr",
		"usr/bin",
		"usr/bin/controller",
		"usr/lib",
		"etc/config",
	} {
		index.set(name, officialPathState{present: true})
	}
	index.removeSubtree("usr/bin")
	for _, removed := range []string{"usr/bin", "usr/bin/controller"} {
		if _, found := index.states[removed]; found {
			t.Fatalf("subtree entry %q remains", removed)
		}
	}
	for _, retained := range []string{"usr", "usr/lib", "etc/config"} {
		if _, found := index.states[retained]; !found {
			t.Fatalf("unrelated entry %q was removed", retained)
		}
	}
}

func mustRequiredInvocationPaths(
	t *testing.T,
	invocation containerInvocation,
) []string {
	t.Helper()
	paths, err := requiredInvocationPaths(invocation)
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func mountedConfigFileForTest(destination, content string) mountedConfigFile {
	digest := sha256.Sum256([]byte(content))
	return mountedConfigFile{
		Source:      namespacedObjectKey("test", "config"),
		Key:         path.Base(destination),
		Destination: destination,
		SHA256:      hex.EncodeToString(digest[:]),
		Content:     []byte(content),
	}
}
