package kube

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

var exactAuthenticationConfiguration = semver.MustParse("1.34.0")

// AuthenticationConfigAPIVersion returns the exact structured authentication
// API supported by the selected Kubernetes release.
func AuthenticationConfigAPIVersion(kubernetes string) (string, error) {
	version, err := semver.NewVersion(strings.TrimPrefix(kubernetes, "v"))
	if err != nil {
		return "", fmt.Errorf(
			"parse selected Kubernetes version %q: %w",
			kubernetes,
			err,
		)
	}
	if version.LessThan(exactAuthenticationConfiguration) {
		return "", fmt.Errorf(
			"Kubernetes %s lacks the required v1 AuthenticationConfiguration API",
			kubernetes,
		)
	}
	return "v1", nil
}
