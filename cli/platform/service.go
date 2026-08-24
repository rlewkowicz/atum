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
	Logger        *slog.Logger
	Runner        process.Runner
	Environment   Environment
	DryRun        bool
	Out           io.Writer
	Orchestration *orchestration.Service
	FluxBin       string
}

type PrepareOptions struct {
	Timeout     time.Duration
	Parallelism int
}

type ApplyOptions struct {
	Timeout time.Duration
}

type ResourceStatus struct {
	Name  string `json:"name"`
	Ready bool   `json:"ready"`
}

type Status struct {
	BundleSHA256            string           `json:"bundleSha256"`
	SourceCommit            string           `json:"sourceCommit"`
	ActiveProfile           string           `json:"activeProfile"`
	BundleReady             bool             `json:"bundleReady"`
	FluxReady               bool             `json:"fluxReady"`
	PrepReady               bool             `json:"prepReady"`
	ProfilePrepReady        bool             `json:"profilePrepReady"`
	BigBangReady            bool             `json:"bigBangReady"`
	ProfileAccessReady      bool             `json:"profileAccessReady"`
	ProfileIdentityRequired bool             `json:"profileIdentityRequired,omitempty"`
	ProfileIdentityReady    bool             `json:"profileIdentityReady"`
	ProfileIdentityFailure  string           `json:"profileIdentityFailure,omitempty"`
	OCISources              []ResourceStatus `json:"ociSources"`
	HelmReleases            []ResourceStatus `json:"helmReleases"`
	LoadBalancerRequired    bool             `json:"loadBalancerRequired,omitempty"`
	LoadBalancerReady       bool             `json:"loadBalancerReady"`
	PublicIngressVIP        string           `json:"publicIngressVip,omitempty"`
	PublicIngressIPs        []string         `json:"publicIngressIps,omitempty"`
	PassthroughIngressVIP   string           `json:"passthroughIngressVip,omitempty"`
	PassthroughIngressIPs   []string         `json:"passthroughIngressIps,omitempty"`
	LoadBalancerRange       string           `json:"loadBalancerRange,omitempty"`
	CertificatesRequired    bool             `json:"certificatesRequired,omitempty"`
	CertificatesReady       bool             `json:"certificatesReady"`
	IssuerReady             bool             `json:"issuerReady"`
	RootCAFingerprint       string           `json:"rootCaFingerprint,omitempty"`
	Certificates            []ResourceStatus `json:"certificates,omitempty"`
	AccessDomain            string           `json:"accessDomain,omitempty"`
	AccessURLs              []string         `json:"accessUrls,omitempty"`
	RoutesReady             bool             `json:"routesReady"`
	HostAccessObserved      bool             `json:"hostAccessObserved,omitempty"`
	LocalDNSReady           bool             `json:"localDnsReady"`
	ResolverReady           bool             `json:"resolverReady"`
	PublicDNSReady          bool             `json:"publicDnsReady"`
	PassthroughDNSReady     bool             `json:"passthroughDnsReady"`
	ResolverPath            string           `json:"resolverPath,omitempty"`
	CATrustReady            bool             `json:"caTrustReady"`
	CAPath                  string           `json:"caPath,omitempty"`
	CAFingerprint           string           `json:"caFingerprint,omitempty"`
	ActiveHelmReleases      int              `json:"activeHelmReleases"`
	ReadyHelmReleases       int              `json:"readyHelmReleases"`
	ActiveWorkloads         int              `json:"activeWorkloads"`
	ReadyWorkloads          int              `json:"readyWorkloads"`
	NonReadyPods            int              `json:"nonReadyPods"`
	InternalImageOnly       bool             `json:"internalImageOnly"`
	ImageIssueCount         int              `json:"imageIssueCount,omitempty"`
	ImageIssues             []string         `json:"imageIssues,omitempty"`
	InternalSourcesOnly     bool             `json:"internalSourcesOnly"`
	SourceIssueCount        int              `json:"sourceIssueCount,omitempty"`
	SourceIssues            []string         `json:"sourceIssues,omitempty"`
}

func (status Status) Ready() bool {
	hostReady := !status.HostAccessObserved || !status.LoadBalancerRequired ||
		(status.LocalDNSReady && status.CATrustReady &&
			status.CAFingerprint != "" && status.CAFingerprint == status.RootCAFingerprint)
	return status.BundleReady && status.FluxReady && status.PrepReady && status.ProfilePrepReady &&
		status.BigBangReady && status.ProfileAccessReady &&
		(!status.ProfileIdentityRequired ||
			(status.ProfileIdentityReady && status.ProfileIdentityFailure == "")) &&
		(!status.LoadBalancerRequired || status.LoadBalancerReady) &&
		(!status.CertificatesRequired || (status.CertificatesReady && status.RoutesReady)) &&
		hostReady &&
		status.ActiveHelmReleases > 0 && status.ActiveHelmReleases == status.ReadyHelmReleases &&
		status.ActiveWorkloads == status.ReadyWorkloads &&
		status.NonReadyPods == 0 && status.InternalImageOnly && status.InternalSourcesOnly
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

func (service Service) deploymentBundle(ctx context.Context) (*delivery.DeploymentBundle, error) {
	return delivery.MaterializeLockedBundle(ctx, service.Project)
}

func timeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultReadinessTimeout
	}
	return timeout
}

func (service Service) credentials(ctx context.Context) (atumsecrets.Document, error) {
	if service.DryRun {
		return atumsecrets.Load(service.Project)
	}
	return atumsecrets.Ensure(ctx, service.Project, service.logger())
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
