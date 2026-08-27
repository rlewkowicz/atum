SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

CONTROLLER_GEN := go tool controller-gen
CRD := config/crd/bases/platform.atum.dev_platformidentityconfigurations.yaml
ROLE := config/rbac/role.yaml
PLATFORM_CRD := platform/apps/atum-operator/crd.yaml
PLATFORM_ROLE := platform/apps/atum-operator/controller-role.yaml

.PHONY: generate manifests project-operator verify-operator

generate:
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./operator/api/..."

manifests:
	$(CONTROLLER_GEN) \
		rbac:roleName=atum-operator \
		crd \
		paths="./operator/..." \
		output:crd:artifacts:config=config/crd/bases \
		output:rbac:artifacts:config=config/rbac

project-operator: generate manifests
	cp "$(CRD)" "$(PLATFORM_CRD)"
	cp "$(ROLE)" "$(PLATFORM_ROLE)"

verify-operator: project-operator
	git diff --exit-code -- \
		operator/api/v1alpha1/zz_generated.deepcopy.go \
		"$(CRD)" "$(ROLE)" "$(PLATFORM_CRD)" "$(PLATFORM_ROLE)"
