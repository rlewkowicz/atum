package delivery

import (
	"errors"
	"log/slog"
	"os"

	"atum/cli/config"
	"atum/cli/process"
)

const (
	defaultGroup       = "platform"
	defaultParallelism = 8
	buildDirectory     = "platform/build"
	bakeFilename       = "docker-bake.hcl"
)

type Environment func(string) string

type Service struct {
	root   string
	logger *slog.Logger
	runner process.Runner
	env    Environment
	docker string
}

type PublishOptions struct {
	Profile     string
	Group       string
	Targets     []string
	Force       bool
	Parallelism int
}

type BundleOptions struct {
	Locked    bool
	Reproduce bool
	Push      bool
	Publish   PublishOptions
}

type PublishResult struct {
	Lock        config.ImageLock
	Published   int
	Reused      int
	LockChanged bool
}

type BundleResult struct {
	Bundle config.Bundle
	Path   string
}

func NewService(
	root string,
	logger *slog.Logger,
	runner process.Runner,
	environment Environment,
	docker string,
) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if runner == nil {
		runner = process.ExecRunner{}
	}
	if environment == nil {
		environment = os.Getenv
	}
	if docker == "" {
		return nil, errors.New("validated Docker preflight identity is required")
	}
	return &Service{root: root, logger: logger, runner: runner, env: environment, docker: docker}, nil
}

type selectedImage struct {
	Image    config.Image
	Delivery config.LockedDelivery
	InputSHA string
}
