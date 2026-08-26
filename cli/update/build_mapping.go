package update

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"atum/cli/config"
)

const buildGraphFile = "platform/build/docker-bake.hcl"

type compatibilityTarget struct {
	image    config.Image
	stage    string
	contexts map[string]string
}

func mappedUpstreamVersion(reference, prefix string) (string, string, error) {
	tag := imageTag(reference)
	if tag == "" {
		return "", "", errors.New("image tag is empty")
	}
	version := strings.TrimPrefix(tag, prefix)
	if version == "" || prefix+version != tag {
		return "", "", fmt.Errorf("tag %q does not use prefix %q", tag, prefix)
	}
	return version, tag, nil
}

func renderBuildGraph(desired config.Document) ([]byte, error) {
	targets := make([]compatibilityTarget, 0, 4)
	for _, image := range desired.Delivery.Images {
		choice := image.Delivery.Default
		if choice.Type != "build" {
			continue
		}
		if image.Compatibility == nil ||
			len(image.Compatibility.Observations) == 0 ||
			image.Compatibility.OfficialMaterial == "" {
			return nil, fmt.Errorf("build image %s has no current compatibility evidence", image.ID)
		}
		target := compatibilityTarget{
			image:    image,
			contexts: make(map[string]string, 2),
		}
		primaryContext := ""
		switch {
		case choice.BakeTarget == "garage-init-helper":
			target.stage = "garage-init-helper"
		case choice.BakeTarget == "grafana-plugins":
			target.stage = "grafana-plugins"
			primaryContext = "atum_grafana_upstream"
		case strings.HasPrefix(choice.BakeTarget, "kubectl-helper-") &&
			strings.HasSuffix(choice.BakeTarget, "-compat"):
			target.stage = "kubectl-helper"
			primaryContext = "atum_kubectl_upstream"
		case strings.HasPrefix(choice.BakeTarget, "postgresql-") &&
			strings.HasSuffix(choice.BakeTarget, "-compat"):
			target.stage = "postgresql-compat"
			primaryContext = "atum_postgresql_upstream"
		case choice.BakeTarget == "vault-curl-compat":
			target.stage = "vault-curl-compat"
			primaryContext = "atum_vault_upstream"
			curlMaterial, found := materialWithPrefix(
				choice.Materials,
				"docker.io/curlimages/curl@sha256:",
			)
			if !found {
				return nil, fmt.Errorf(
					"build image %s has no immutable official curl material",
					image.ID,
				)
			}
			target.contexts["atum_curl_upstream"] = curlMaterial
		default:
			return nil, fmt.Errorf(
				"build image %s has unsupported compatibility target %s",
				image.ID,
				choice.BakeTarget,
			)
		}
		if !containsString(
			choice.Materials,
			image.Compatibility.OfficialMaterial,
		) {
			return nil, fmt.Errorf(
				"build image %s official material is not a declared build input",
				image.ID,
			)
		}
		if primaryContext != "" {
			target.contexts[primaryContext] =
				image.Compatibility.OfficialMaterial
		}
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].image.Delivery.Default.BakeTarget <
			targets[j].image.Delivery.Default.BakeTarget
	})

	sbomTarget := ""
	for _, image := range desired.Delivery.Images {
		if image.ID == "sbom-scanner" {
			sbomTarget = image.Target
			break
		}
	}
	if sbomTarget == "" {
		return nil, errors.New("delivery graph requires the SBOM scanner image")
	}

	var graph strings.Builder
	writeVariable := func(name, value string) {
		fmt.Fprintf(
			&graph,
			"variable %s {\n  default = %s\n}\n\n",
			strconv.Quote(name),
			strconv.Quote(value),
		)
	}
	writeVariable(
		"ATUM_CACHE_REGISTRY",
		strings.TrimSuffix(desired.Delivery.Registry.Host, "/")+"/buildkit",
	)
	writeVariable(
		"ATUM_BOOTSTRAP_OUTPUT",
		"type=registry,oci-mediatypes=true,rewrite-timestamp=true",
	)
	writeVariable("ATUM_DEBIAN_IMAGE", desired.Delivery.Policy.BuildBase)
	writeVariable("ATUM_PLATFORM", desired.Project.Platform)
	writeVariable("ATUM_SBOM_GENERATOR_IMAGE", sbomTarget)
	writeVariable("SOURCE_DATE_EPOCH", "0")

	graph.WriteString("group \"default\" {\n  targets = [")
	for index := range targets {
		if index != 0 {
			graph.WriteString(", ")
		}
		graph.WriteString(strconv.Quote(targets[index].image.Delivery.Default.BakeTarget))
	}
	graph.WriteString("]\n}\n\n")
	graph.WriteString(`target "_common" {
  context   = "."
  platforms = [ATUM_PLATFORM]
  args = {
    ATUM_DEBIAN_IMAGE = ATUM_DEBIAN_IMAGE
    ATUM_IMAGE_CREATED = "1970-01-01T00:00:00Z"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
  }
  output = ["type=image,oci-mediatypes=true,rewrite-timestamp=true"]
}

target "_attested" {
  inherits = ["_common"]
  attest = [
    "type=provenance,mode=max",
    "type=sbom,generator=${ATUM_SBOM_GENERATOR_IMAGE}",
  ]
}

`)
	for _, target := range targets {
		name := target.image.Delivery.Default.BakeTarget
		fmt.Fprintf(&graph, "target %s {\n", strconv.Quote(name))
		graph.WriteString("  inherits   = [\"_attested\"]\n")
		graph.WriteString("  dockerfile = \"docker/Dockerfile.delivery\"\n")
		fmt.Fprintf(&graph, "  target     = %s\n", strconv.Quote(target.stage))
		fmt.Fprintf(&graph, "  tags       = [%s]\n", strconv.Quote(target.image.Target))
		if len(target.contexts) != 0 {
			graph.WriteString("  contexts = {\n")
			contextNames := make([]string, 0, len(target.contexts))
			for name := range target.contexts {
				contextNames = append(contextNames, name)
			}
			sort.Strings(contextNames)
			for _, contextName := range contextNames {
				fmt.Fprintf(
					&graph,
					"    %s = %s\n",
					contextName,
					strconv.Quote(
						"docker-image://"+target.contexts[contextName],
					),
				)
			}
			graph.WriteString("  }\n")
		}
		args := map[string]string{
			"ATUM_IMAGE_LICENSE": target.image.License,
			"ATUM_IMAGE_SOURCE":  target.image.Provenance,
			"ATUM_IMAGE_VERSION": imageTag(target.image.Target),
		}
		if name == "grafana-plugins" {
			args["ATUM_IMAGE_REVISION"] =
				target.image.Compatibility.Observations[0].RuntimeContractSHA256
		}
		argNames := make([]string, 0, len(args))
		for argName := range args {
			argNames = append(argNames, argName)
		}
		sort.Strings(argNames)
		graph.WriteString("  args = {\n")
		for _, argName := range argNames {
			fmt.Fprintf(
				&graph,
				"    %s = %s\n",
				argName,
				strconv.Quote(args[argName]),
			)
		}
		graph.WriteString("  }\n")
		fmt.Fprintf(
			&graph,
			"  cache-from = [\"type=registry,ref=${ATUM_CACHE_REGISTRY}/%s:cache\"]\n",
			name,
		)
		fmt.Fprintf(
			&graph,
			"  cache-to   = [\"type=registry,ref=${ATUM_CACHE_REGISTRY}/%s:cache,mode=max,image-manifest=true,oci-mediatypes=true\"]\n",
			name,
		)
		graph.WriteString("}\n\n")
	}
	return []byte(strings.TrimRight(graph.String(), "\n") + "\n"), nil
}

func materialWithPrefix(materials []string, prefix string) (string, bool) {
	for _, material := range materials {
		if strings.HasPrefix(material, prefix) {
			return material, true
		}
	}
	return "", false
}
