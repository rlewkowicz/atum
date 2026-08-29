package update

import "atum/cli/config"

// projectSSHIdentity supplies the current default only when the human-owned
// active-target declaration is absent. Once declared, the updater preserves
// the configured private path and the public half remains mechanically paired.
func projectSSHIdentity(desired *config.Document) {
	target, exists := desired.Infrastructure.Targets[desired.Infrastructure.Active]
	if !exists {
		return
	}
	if target.SSH.PrivateKeyPath == "" {
		target.SSH.PrivateKeyPath = config.DefaultSSHPrivateKeyPath
		desired.Infrastructure.Targets[desired.Infrastructure.Active] = target
	}
}
