package delivery

import (
	"context"
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

type PublishResult struct {
	Lock      config.ImageLock
	Published int
	Reused    int
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

func effectiveParallelism(requested, configured int) int {
	return config.EffectiveWorkLimit(requested, configured, defaultParallelism)
}

type deliveryBudgetKey struct{}

func withDeliveryBudget(ctx context.Context, parallelism int) context.Context {
	if _, exists := ctx.Value(deliveryBudgetKey{}).(chan struct{}); exists {
		return ctx
	}
	return context.WithValue(
		ctx, deliveryBudgetKey{}, make(chan struct{}, effectiveParallelism(parallelism, 0)),
	)
}

func runDeliveryWorker(ctx context.Context, work func() error) error {
	budget, exists := ctx.Value(deliveryBudgetKey{}).(chan struct{})
	if !exists {
		return work()
	}
	select {
	case budget <- struct{}{}:
		defer func() { <-budget }()
		return work()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func runExclusiveDeliveryWork(ctx context.Context, work func() error) error {
	budget, exists := ctx.Value(deliveryBudgetKey{}).(chan struct{})
	if !exists {
		return work()
	}
	acquired := 0
	for acquired < cap(budget) {
		select {
		case budget <- struct{}{}:
			acquired++
		case <-ctx.Done():
			for acquired > 0 {
				<-budget
				acquired--
			}
			return ctx.Err()
		}
	}
	defer func() {
		for acquired > 0 {
			<-budget
			acquired--
		}
	}()
	return work()
}
