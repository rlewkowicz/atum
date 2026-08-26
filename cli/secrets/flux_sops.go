package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"atum/cli/config"
	"atum/cli/fssecure"
	"atum/cli/secretvalue"

	"filippo.io/age"
)

const (
	fluxAgeIdentityPath = ".atum/state/flux-sops.agekey"
	fluxAgeLockPath     = ".atum/state/flux-sops-age.lock"
)

// FluxAgeIdentity is the local bridge credential required by Flux to decrypt
// the SOPS source. The public recipient may be retained; the identity must be
// cleared after its one private subprocess handoff.
type FluxAgeIdentity struct {
	encoded   secretvalue.Value
	recipient string
}

func EnsureFluxAgeIdentity(
	ctx context.Context,
	project *config.Project,
) (*FluxAgeIdentity, error) {
	if ctx == nil {
		return nil, errors.New("Flux SOPS context is required")
	}
	if project == nil {
		return nil, errors.New("Atum project is required")
	}
	unlock, err := fssecure.LockContext(
		ctx, project.Root, fluxAgeLockPath, 25*time.Millisecond,
	)
	if err != nil {
		return nil, fmt.Errorf("lock Flux SOPS identity: %w", err)
	}
	defer unlock()

	data, exists, err := readOptional(project.Root, fluxAgeIdentityPath, true)
	if err != nil {
		return nil, fmt.Errorf("read Flux SOPS identity: %w", err)
	}
	if !exists {
		generated, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, fmt.Errorf("generate Flux SOPS age identity: %w", err)
		}
		data = append([]byte(generated.String()), '\n')
		if err := fssecure.CreateRegularWith(
			project.Root,
			fluxAgeIdentityPath,
			0o600,
			func(destination io.Writer) error {
				_, err := destination.Write(data)
				return err
			},
		); err != nil {
			clear(data)
			if !errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("persist Flux SOPS age identity: %w", err)
			}
			data, exists, err = readOptional(project.Root, fluxAgeIdentityPath, true)
			if err != nil || !exists {
				return nil, fmt.Errorf("read concurrently created Flux SOPS identity: %w", err)
			}
		}
	}
	defer clear(data)

	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse Flux SOPS age identity: %w", err)
	}
	return &FluxAgeIdentity{
		encoded:   secretvalue.New(data),
		recipient: identity.Recipient().String(),
	}, nil
}

func (identity *FluxAgeIdentity) Recipient() string {
	if identity == nil {
		return ""
	}
	return identity.recipient
}

func (identity *FluxAgeIdentity) MarshalAnsibleJSON() ([]byte, error) {
	if identity == nil || len(identity.encoded) == 0 || identity.recipient == "" {
		return nil, errors.New("Flux SOPS age identity is unavailable")
	}
	return secretvalue.MarshalProjection(
		"atum_flux_sops_keys",
		secretvalue.Values{"identity.agekey": identity.encoded},
		"atum_flux_sops_recipient",
		[]byte(identity.recipient),
		fileLimit,
	)
}

func (identity *FluxAgeIdentity) Clear() {
	if identity == nil {
		return
	}
	identity.encoded.Clear()
	identity.recipient = ""
}
