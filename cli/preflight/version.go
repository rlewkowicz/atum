package preflight

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

type terraformVersion struct {
	Version string `json:"terraform_version"`
}

func dockerVersionParser(output string) (string, string, error) {
	fields := strings.Fields(output)
	if len(fields) != 2 {
		return "", "", errors.New("returned an invalid Docker client/server identity")
	}
	clientKey, client, clientFound := strings.Cut(fields[0], "=")
	serverKey, server, serverFound := strings.Cut(fields[1], "=")
	if !clientFound || !serverFound || clientKey != "client" || serverKey != "server" ||
		client == "" || server == "" {
		return "", "", errors.New("returned an invalid Docker client/server identity")
	}
	identity := "client=" + client + " server=" + server
	return identity, identity, nil
}

func checkTerraformVersion(data, constraint string) (string, error) {
	var identity terraformVersion
	if err := json.Unmarshal([]byte(data), &identity); err != nil {
		return "", errors.New("returned invalid version JSON")
	}
	version, err := semver.NewVersion(strings.TrimSpace(identity.Version))
	if err != nil {
		return "", errors.New("returned an invalid version identity")
	}
	required, err := semver.NewConstraint(constraint)
	if err != nil {
		return "", fmt.Errorf("project has invalid required_version %q", constraint)
	}
	if !required.Check(version) {
		return version.String(), fmt.Errorf("version %s does not satisfy required_version %s", version, constraint)
	}
	return version.String(), nil
}

func checkFluxVersion(data, targetVersion string) (string, error) {
	fields := strings.Fields(data)
	if len(fields) != 3 || !strings.EqualFold(fields[0], "flux") ||
		!strings.EqualFold(fields[1], "version") {
		return "", errors.New("returned an invalid version identity")
	}
	installed, err := semver.NewVersion(strings.TrimPrefix(fields[2], "v"))
	if err != nil {
		return "", errors.New("returned an invalid version identity")
	}
	target, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(targetVersion), "v"))
	if err != nil {
		return "", errors.New("project has an invalid declarative Flux version")
	}
	if installed.Prerelease() != "" || installed.Major() != target.Major() ||
		installed.Minor() != target.Minor() {
		return installed.String(), fmt.Errorf(
			"version %s is incompatible; require stable %d.%d.x",
			installed,
			target.Major(),
			target.Minor(),
		)
	}
	return installed.String(), nil
}

func veleroVersionParser(output string) (string, string, error) {
	var version string
	fields := strings.Fields(output)
	if len(fields) < 3 || !strings.EqualFold(fields[0], "Client:") {
		return "", "", errors.New("returned an invalid Velero client identity")
	}
	for index, field := range fields {
		if !strings.EqualFold(field, "Version:") {
			continue
		}
		if index+1 == len(fields) || fields[index+1] == "" || version != "" {
			return "", "", errors.New("returned an invalid Velero client identity")
		}
		version = fields[index+1]
	}
	if version == "" {
		return "", "", errors.New("returned an invalid Velero client identity")
	}
	return version, version, nil
}
