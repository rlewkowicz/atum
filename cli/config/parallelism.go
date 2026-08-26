package config

import "runtime"

const DefaultWorkLimit = 8

func EffectiveWorkLimit(requested, configured, fallback int) int {
	if requested <= 0 {
		requested = configured
	}
	if requested <= 0 {
		requested = fallback
	}
	if requested <= 0 {
		requested = DefaultWorkLimit
	}
	return min(max(requested, 1), runtime.GOMAXPROCS(0), 24)
}
