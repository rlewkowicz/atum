package platform

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/fssecure"
	atumoci "atum/cli/oci"
	"atum/cli/progress"
	atumsecrets "atum/cli/secrets"
	"atum/cli/secretvalue"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/goharbor/go-client/pkg/harbor"
	harborclient "github.com/goharbor/go-client/pkg/sdk/v2.0/client"
	"github.com/goharbor/go-client/pkg/sdk/v2.0/client/health"
	"github.com/goharbor/go-client/pkg/sdk/v2.0/client/immutable"
	"github.com/goharbor/go-client/pkg/sdk/v2.0/client/project"
	"github.com/goharbor/go-client/pkg/sdk/v2.0/models"
	"golang.org/x/sync/errgroup"
	"helm.sh/helm/v4/pkg/registry"
	"k8s.io/apimachinery/pkg/util/wait"
	"oras.land/oras-go/v2/errdef"
)

type registryCredentials struct {
	Username string
	Password secretvalue.Value
	CA       []byte
}

func (credentials *registryCredentials) Clear() {
	if credentials == nil {
		return
	}
	credentials.Username = ""
	credentials.Password.Clear()
	clear(credentials.CA)
	credentials.CA = nil
}

type harborControl struct {
	target   config.Registry
	password secretvalue.Value
}

func (control *harborControl) Clear() {
	if control == nil {
		return
	}
	control.target = config.Registry{}
	control.password.Clear()
}

func (service Service) configureHarbor(
	ctx context.Context,
	credentials atumsecrets.Document,
	timeout time.Duration,
) (registryCredentials, error) {
	control, err := newHarborControl(
		service.Project.Desired.Delivery.Registry,
		credentials.Harbor.AdminPassword,
	)
	if err != nil {
		return registryCredentials{}, err
	}
	defer control.Clear()
	if err := control.waitHealthy(ctx, timeout); err != nil {
		return registryCredentials{}, err
	}
	for _, desired := range []struct {
		name   string
		public bool
	}{
		{name: "atum", public: true},
		{name: "charts", public: true},
		{name: "buildkit"},
		{name: "seed-artifacts"},
	} {
		if err := control.ensureProject(ctx, desired.name, desired.public); err != nil {
			return registryCredentials{}, err
		}
	}
	if err := control.ensureChartsImmutable(ctx); err != nil {
		return registryCredentials{}, err
	}
	return registryCredentials{
		Username: "admin",
		Password: credentials.Harbor.AdminPassword.Clone(),
	}, nil
}

func newHarborControl(
	target config.Registry,
	password secretvalue.Value,
) (*harborControl, error) {
	if len(password) == 0 {
		return nil, errors.New("Harbor administrator password is required")
	}
	if _, err := harborEndpoint(target); err != nil {
		return nil, err
	}
	return &harborControl{target: target, password: password.Clone()}, nil
}

func harborEndpoint(target config.Registry) (*url.URL, error) {
	scheme := "http"
	if target.TLSVerify {
		scheme = "https"
	}
	endpoint, err := url.Parse(scheme + "://" + target.Host)
	if err != nil || endpoint.Host != target.Host || endpoint.Path != "" {
		return nil, fmt.Errorf("parse Harbor API endpoint %s: %w", target.Host, err)
	}
	return endpoint, nil
}

func (control *harborControl) apiClient() (*harborclient.HarborAPI, error) {
	endpoint, err := harborEndpoint(control.target)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.ResponseHeaderTimeout = 30 * time.Second
	if control.target.TLSVerify {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	password := string(control.password.Bytes())
	configuration := (&harbor.Config{
		URL: endpoint, Transport: transport, AuthInfo: httptransport.BasicAuth("admin", password),
	}).ToV2Config()
	password = ""
	return harborclient.New(configuration), nil
}

func (control *harborControl) waitHealthy(ctx context.Context, timeout time.Duration) error {
	client, err := control.apiClient()
	if err != nil {
		return err
	}
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		response, err := client.Health.GetHealth(ctx, health.NewGetHealthParams())
		if err != nil || response == nil || response.Payload == nil || response.Payload.Status != "healthy" {
			return false, nil
		}
		for _, component := range response.Payload.Components {
			if component == nil || component.Status != "healthy" {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("wait for Harbor health: %w", err)
	}
	return nil
}

func (control *harborControl) ensureProject(ctx context.Context, name string, public bool) error {
	client, err := control.apiClient()
	if err != nil {
		return err
	}
	page, pageSize, detail := int64(1), int64(2), true
	result, err := client.Project.ListProjects(ctx, &project.ListProjectsParams{
		Name: &name, Page: &page, PageSize: &pageSize, WithDetail: &detail,
	})
	if err != nil {
		return fmt.Errorf("list Harbor project %s: %w", name, err)
	}
	metadata := projectMetadata(public)
	request := &models.ProjectReq{ProjectName: name, Metadata: metadata, Public: &public}
	for _, current := range result.Payload {
		if current != nil && current.Name == name && !current.Deleted {
			isName := true
			_, err = client.Project.UpdateProject(ctx, &project.UpdateProjectParams{
				ProjectNameOrID: name, XIsResourceName: &isName, Project: request,
			})
			if err != nil {
				return fmt.Errorf("update Harbor project %s: %w", name, err)
			}
			return nil
		}
	}
	if result.XTotalCount > pageSize {
		return fmt.Errorf("Harbor project lookup for %s returned an unexpected unbounded result", name)
	}
	storage := int64(-1)
	request.StorageLimit = &storage
	if _, err := client.Project.CreateProject(ctx, &project.CreateProjectParams{Project: request}); err != nil {
		return fmt.Errorf("create Harbor project %s: %w", name, err)
	}
	return nil
}

func projectMetadata(public bool) *models.ProjectMetadata {
	falseValue, severity, visibility := "false", "critical", fmt.Sprint(public)
	return &models.ProjectMetadata{
		Public: visibility, AutoScan: &falseValue, EnableContentTrust: &falseValue,
		PreventVul: &falseValue, Severity: &severity,
	}
}

func (service Service) publishBundle(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	credentials registryCredentials,
	parallelism int,
) error {
	if parallelism <= 0 {
		parallelism = service.Project.Desired.Updates.Parallelism
	}
	parallelism = config.EffectiveWorkLimit(
		parallelism,
		service.Project.Desired.Updates.Parallelism,
		config.DefaultWorkLimit,
	)
	registryTarget := service.Project.Desired.Delivery.Registry
	nativeCredentials := atumoci.Credentials{
		Username: credentials.Username,
		Password: credentials.Password.Clone(),
		CACert:   append([]byte(nil), credentials.CA...),
	}
	defer nativeCredentials.Clear()
	client, err := atumoci.NewClient(registryTarget, nativeCredentials)
	if err != nil {
		return err
	}
	defer client.Clear()
	store, err := bundle.ImageStore()
	if err != nil {
		return fmt.Errorf("open verified bundled OCI layout: %w", err)
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(parallelism)
	total := len(bundle.Images) + len(bundle.Charts)
	var publishedCount atomic.Int64
	for _, image := range bundle.Images {
		image := image
		group.Go(func() error {
			if _, err := client.Resolve(groupContext, image.Target); err != nil && !errors.Is(err, errdef.ErrNotFound) {
				return err
			}
			published, err := client.CopyFromStore(groupContext, store, image.Digest, image.Target)
			if err != nil {
				return err
			}
			if published.Digest.String() != image.Digest {
				return fmt.Errorf("publish %s produced %s, want %s", image.Target, published.Digest, image.Digest)
			}
			resolved, err := client.Resolve(groupContext, image.Target)
			if err != nil {
				return fmt.Errorf("resolve published image %s: %w", image.Target, err)
			}
			if resolved.Digest.String() != image.Digest {
				return fmt.Errorf("published image %s resolves to %s, want %s", image.Target, resolved.Digest, image.Digest)
			}
			current := int(publishedCount.Add(1))
			progress.Update(groupContext, progress.Platform, "harbor-seed", "Seed Harbor publication",
				"published runtime image "+image.ID, current, total)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}
	progress.Update(ctx, progress.Platform, "chart-publication", "Chart publication",
		"publishing immutable chart inventory", 0, len(bundle.Charts))
	var chartCount atomic.Int64
	return service.publishCharts(ctx, bundle, credentials, parallelism, func(id string) {
		chartCurrent := int(chartCount.Add(1))
		progress.Update(ctx, progress.Platform, "chart-publication", "Chart publication",
			"published or reused chart "+id, chartCurrent, len(bundle.Charts))
		current := int(publishedCount.Add(1))
		progress.Update(ctx, progress.Platform, "harbor-seed", "Seed Harbor publication",
			"published chart "+id, current, total)
	})
}

func (service Service) publishCharts(
	ctx context.Context,
	bundle *delivery.DeploymentBundle,
	credentials registryCredentials,
	parallelism int,
	report func(string),
) error {
	charts := append([]delivery.BundleChart(nil), bundle.Charts...)
	sort.Slice(charts, func(i, j int) bool { return charts[i].ID < charts[j].ID })
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism,
		service.Project.Desired.Updates.Parallelism,
		config.DefaultWorkLimit,
	))
	for index := range charts {
		chart := charts[index]
		group.Go(func() error {
			if err := service.publishChart(groupContext, chart, credentials); err != nil {
				return err
			}
			report(chart.ID)
			return nil
		})
	}
	return group.Wait()
}

func (service Service) publishChart(
	ctx context.Context,
	chart delivery.BundleChart,
	credentials registryCredentials,
) error {
	client, err := service.helmRegistryClient(credentials, chart.ArchiveSHA256)
	if err != nil {
		return err
	}
	nativeCredentials := atumoci.Credentials{
		Username: credentials.Username,
		Password: credentials.Password.Clone(),
		CACert:   append([]byte(nil), credentials.CA...),
	}
	defer nativeCredentials.Clear()
	resolver, err := atumoci.NewClient(
		service.Project.Desired.Delivery.Registry, nativeCredentials,
	)
	if err != nil {
		return err
	}
	defer resolver.Clear()
	if chart.Size <= 0 || chart.Size > config.ChartArchiveLimit {
		return fmt.Errorf("chart %s has invalid locked size %d", chart.ID, chart.Size)
	}
	data, err := readBounded(chart.Path, config.ChartArchiveLimit)
	if err != nil {
		return fmt.Errorf("read chart %s: %w", chart.ID, err)
	}
	defer clear(data)
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != chart.ArchiveSHA256 {
		return fmt.Errorf("chart %s archive changed after bundle verification", chart.ID)
	}
	archiveSize := int64(len(data))
	if archiveSize != chart.Size {
		return fmt.Errorf("chart %s is %d bytes, want %d", chart.ID, archiveSize, chart.Size)
	}
	descriptor, resolveErr := resolver.Resolve(ctx, chart.Target)
	if resolveErr == nil {
		if err := resolver.ValidateHelmChart(
			ctx, chart.Target, descriptor, chart.ArchiveSHA256, archiveSize,
		); err != nil {
			return fmt.Errorf("immutable Harbor chart %s differs from the bundle: %w", chart.Target, err)
		}
		return nil
	}
	if !errors.Is(resolveErr, errdef.ErrNotFound) {
		return resolveErr
	}
	result, err := client.Push(
		data,
		chart.Target,
		registry.PushOptCreationTime(time.Unix(0, 0).UTC().Format(time.RFC3339)),
	)
	if err != nil {
		return fmt.Errorf("publish chart %s: %w", chart.ID, err)
	}
	if result == nil || result.Manifest == nil || result.Manifest.Digest == "" {
		return fmt.Errorf("publish chart %s returned no manifest digest", chart.ID)
	}
	verified, err := resolver.Resolve(ctx, chart.Target)
	if err != nil {
		return fmt.Errorf("verify published chart %s: %w", chart.ID, err)
	}
	if verified.Digest.String() != result.Manifest.Digest {
		return fmt.Errorf("published chart %s does not resolve to its exact manifest and archive", chart.ID)
	}
	if err := resolver.ValidateHelmChart(
		ctx, chart.Target, verified, chart.ArchiveSHA256, archiveSize,
	); err != nil {
		return fmt.Errorf("validate published chart %s: %w", chart.ID, err)
	}
	return nil
}

func (service Service) helmRegistryClient(
	credentials registryCredentials,
	identity string,
) (*registry.Client, error) {
	if len(identity) != 64 {
		return nil, errors.New("Helm registry client requires an immutable chart identity")
	}
	credentialRelative := filepath.Join(
		".atum", "state", "helm-registry-"+identity+".json",
	)
	if _, err := fssecure.OpenRegular(service.Project.Root, credentialRelative); errors.Is(err, os.ErrNotExist) {
		if err := fssecure.WriteRegular(service.Project.Root, credentialRelative, []byte("{}\n"), 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	password := string(credentials.Password.Bytes())
	options := []registry.ClientOption{
		registry.ClientOptBasicAuth(credentials.Username, password),
		registry.ClientOptHTTPClient(&http.Client{Timeout: 10 * time.Minute}),
		registry.ClientOptCredentialsFile(filepath.Join(service.Project.Root, credentialRelative)),
		registry.ClientOptEnableCache(true),
	}
	password = ""
	if !service.Project.Desired.Delivery.Registry.TLSVerify {
		options = append(options, registry.ClientOptPlainHTTP())
	}
	client, err := registry.NewClient(options...)
	if err != nil {
		return nil, fmt.Errorf("initialize Helm registry client: %w", err)
	}
	return client, nil
}

func (control *harborControl) ensureChartsImmutable(ctx context.Context) error {
	client, err := control.apiClient()
	if err != nil {
		return err
	}
	current, err := control.chartsImmutable(ctx, client)
	if err != nil || current {
		return err
	}
	isName := true
	rule := &models.ImmutableRule{
		Action: "immutable", Template: "immutable_template", Params: map[string]any{},
		TagSelectors: []*models.ImmutableSelector{
			{Kind: "doublestar", Decoration: "matches", Pattern: "**"},
		},
		ScopeSelectors: map[string][]models.ImmutableSelector{
			"repository": {{Kind: "doublestar", Decoration: "repoMatches", Pattern: "**"}},
		},
	}
	_, err = client.Immutable.CreateImmuRule(ctx, &immutable.CreateImmuRuleParams{
		ProjectNameOrID: "charts", XIsResourceName: &isName, ImmutableRule: rule,
	})
	if err != nil {
		return fmt.Errorf("create Harbor chart immutability rule: %w", err)
	}
	return nil
}

func (control *harborControl) chartsImmutable(
	ctx context.Context,
	client *harborclient.HarborAPI,
) (bool, error) {
	page, pageSize := int64(1), int64(100)
	isName := true
	response, err := client.Immutable.ListImmuRules(ctx, &immutable.ListImmuRulesParams{
		ProjectNameOrID: "charts", XIsResourceName: &isName, Page: &page, PageSize: &pageSize,
	})
	if err != nil {
		return false, fmt.Errorf("list Harbor chart immutability rules: %w", err)
	}
	if response.XTotalCount > pageSize {
		return false, errors.New("Harbor charts project has more than 100 immutability rules")
	}
	for _, rule := range response.Payload {
		if immutableAllTags(rule) {
			return true, nil
		}
	}
	return false, nil
}

func immutableAllTags(rule *models.ImmutableRule) bool {
	if rule == nil || rule.Disabled || rule.Action != "immutable" || rule.Template != "immutable_template" || len(rule.TagSelectors) != 1 {
		return false
	}
	tag := rule.TagSelectors[0]
	if tag == nil || tag.Kind != "doublestar" || tag.Decoration != "matches" || tag.Pattern != "**" {
		return false
	}
	repositories := rule.ScopeSelectors["repository"]
	return len(repositories) == 1 && repositories[0].Kind == "doublestar" &&
		repositories[0].Decoration == "repoMatches" && repositories[0].Pattern == "**"
}
