// Package platform publishes exact OCI and Git inputs to the Terraform-owned
// seed services, invokes Flux, and observes the declarative platform above a
// healthy Kubespray-managed cluster.
package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/kube"
	"atum/cli/orchestration"
	"atum/cli/process"
	atumsecrets "atum/cli/secrets"
)

const DefaultReadinessTimeout = 6 * time.Hour

type Environment func(string) string

type Service struct {
	Project       *config.Project
	Publication   *delivery.Publication
	Logger        *slog.Logger
	Runner        process.Runner
	Environment   Environment
	DryRun        bool
	Out           io.Writer
	Orchestration *orchestration.Service
	FluxBin       string
	SOPS          atumsecrets.SOPSAdapter
}

type PrepareOptions struct {
	Timeout     time.Duration
	Parallelism int
}

type ApplyOptions struct {
	Timeout time.Duration
}

type ResourceStatus struct {
	Name    string `json:"name"`
	Ready   bool   `json:"ready"`
	Message string `json:"message,omitempty"`
}

type ReconciliationStatus struct {
	GitRepositories       []ResourceStatus `json:"gitRepositories"`
	Kustomizations        []ResourceStatus `json:"kustomizations"`
	OCIRepositories       []ResourceStatus `json:"ociRepositories"`
	HelmReleases          []ResourceStatus `json:"helmReleases"`
	Certificates          []ResourceStatus `json:"certificates"`
	PlatformConfigurations []ResourceStatus `json:"platformConfigurations"`
}

func (status ReconciliationStatus) Complete() bool {
	return resourcesReady(status.GitRepositories) &&
		resourcesReady(status.Kustomizations) &&
		resourcesReady(status.OCIRepositories) &&
		resourcesReady(status.HelmReleases) &&
		resourcesReady(status.Certificates) &&
		resourcesReady(status.PlatformConfigurations)
}

func (status ReconciliationStatus) resourceSets() [][]ResourceStatus {
	return [][]ResourceStatus{
		status.GitRepositories,
		status.Kustomizations,
		status.OCIRepositories,
		status.HelmReleases,
		status.Certificates,
		status.PlatformConfigurations,
	}
}

type DeliveryComplianceStatus struct {
	PublicationExact bool     `json:"publicationExact"`
	ForgejoExact     bool     `json:"forgejoExact"`
	HarborImagesExact bool    `json:"harborImagesExact"`
	HarborChartsExact bool    `json:"harborChartsExact"`
	Issues           []string `json:"issues,omitempty"`
}

func (status DeliveryComplianceStatus) Compliant() bool {
	return status.PublicationExact && status.ForgejoExact &&
		status.HarborImagesExact && status.HarborChartsExact &&
		len(status.Issues) == 0
}

func resourcesReady(resources []ResourceStatus) bool {
	if len(resources) == 0 {
		return false
	}
	for index := range resources {
		if !resources[index].Ready {
			return false
		}
	}
	return true
}

type LocalIntegrationStatus struct {
	Required              bool     `json:"required"`
	LoadBalancerReady     bool     `json:"loadBalancerReady"`
	PublicIngressVIP      string   `json:"publicIngressVip,omitempty"`
	PublicIngressIPs      []string `json:"publicIngressIps,omitempty"`
	PassthroughIngressVIP string   `json:"passthroughIngressVip,omitempty"`
	PassthroughIngressIPs []string `json:"passthroughIngressIps,omitempty"`
	LoadBalancerRange     string   `json:"loadBalancerRange,omitempty"`
	RootCAFingerprint     string   `json:"rootCaFingerprint,omitempty"`
	AccessDomain          string   `json:"accessDomain,omitempty"`
	AccessURLs            []string `json:"accessUrls,omitempty"`
	HostAccessObserved    bool     `json:"hostAccessObserved,omitempty"`
	LocalDNSReady         bool     `json:"localDnsReady"`
	ResolverReady         bool     `json:"resolverReady"`
	PublicDNSReady        bool     `json:"publicDnsReady"`
	PassthroughDNSReady   bool     `json:"passthroughDnsReady"`
	ResolverPath          string   `json:"resolverPath,omitempty"`
	CATrustReady          bool     `json:"caTrustReady"`
	CAPath                string   `json:"caPath,omitempty"`
	CAFingerprint         string   `json:"caFingerprint,omitempty"`
}

func (status LocalIntegrationStatus) Exact() bool {
	if !status.Required {
		return true
	}
	return status.LoadBalancerReady &&
		status.HostAccessObserved && status.LocalDNSReady && status.CATrustReady &&
		status.CAFingerprint != "" && status.CAFingerprint == status.RootCAFingerprint
}

type Status struct {
	PublicationSHA256 string                `json:"publicationSha256"`
	SourceCommit   string                   `json:"sourceCommit"`
	ActiveProfile  string                   `json:"activeProfile"`
	Reconciliation ReconciliationStatus     `json:"reconciliation"`
	Delivery       DeliveryComplianceStatus `json:"delivery"`
	Local          LocalIntegrationStatus   `json:"localIntegration"`
}

func (service Service) Validate() error {
	if service.Project == nil {
		return errors.New("Atum project is not loaded")
	}
	if service.Orchestration == nil {
		return errors.New("orchestration service is required")
	}
	return nil
}

func (service Service) logger() *slog.Logger {
	if service.Logger != nil {
		return service.Logger
	}
	return slog.Default()
}

func (service Service) environment(name string) string {
	if service.Environment != nil {
		return service.Environment(name)
	}
	return os.Getenv(name)
}

func (service Service) cluster() (*kube.Observer, error) {
	return kube.New(service.kubeconfig())
}

func (service Service) kubeconfig() string {
	kubeconfig := service.environment("KUBECONFIG")
	if kubeconfig != "" {
		return kubeconfig
	}
	return filepath.Join(
		service.Project.Root,
		service.Project.Desired.Orchestration.Inventory,
		"artifacts",
		"admin.conf",
	)
}

func timeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultReadinessTimeout
	}
	return timeout
}

func (service Service) credentials(ctx context.Context) (atumsecrets.Document, error) {
	if service.DryRun {
		return atumsecrets.Load(ctx, service.Project, service.SOPS)
	}
	return atumsecrets.Ensure(ctx, service.Project, service.SOPS, service.logger())
}

func (service Service) requireReadyCluster(ctx context.Context) error {
	if err := service.Validate(); err != nil {
		return err
	}
	if service.DryRun {
		return nil
	}
	if err := service.Orchestration.ValidatePlatformPrerequisites(ctx); err != nil {
		return fmt.Errorf("platform preflight: %w", err)
	}
	return nil
}
