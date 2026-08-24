package oci

import (
	"fmt"
	"strings"

	"oras.land/oras-go/v2/registry"
)

// Reference is a validated OCI repository reference split into the fields
// needed by ORAS. Repository never includes a tag or digest.
type Reference struct {
	Registry   string
	Repository string
	Identifier string
}

func ParseReference(value string) (Reference, error) {
	parsed, err := registry.ParseReference(strings.TrimSpace(value))
	if err != nil {
		return Reference{}, fmt.Errorf("parse OCI reference %q: %w", value, err)
	}
	if parsed.Reference == "" {
		return Reference{}, fmt.Errorf("OCI reference %q has no tag or digest", value)
	}
	return Reference{
		Registry:   parsed.Registry,
		Repository: parsed.Repository,
		Identifier: parsed.Reference,
	}, nil
}

func (reference Reference) RepositoryName() string {
	return reference.Registry + "/" + reference.Repository
}

func SeedReference(id string) string {
	return "atum-seed.local/" + id + ":seed"
}
