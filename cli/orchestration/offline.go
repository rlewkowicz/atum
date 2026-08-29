package orchestration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"atum/cli/config"
	"atum/cli/delivery"
	"atum/cli/fssecure"
	atumoci "atum/cli/oci"
	"atum/cli/process"

	"golang.org/x/sync/errgroup"
)

type kubesprayOfflineServer struct {
	server      *http.Server
	listener    net.Listener
	result      chan error
	cleanupCtx  context.Context
	firewallBin string
	runner      process.Runner
	port        int
	openedPort  bool
}

func (server *kubesprayOfflineServer) Close() error {
	if server == nil {
		return nil
	}
	closeErr := server.server.Close()
	serveErr := <-server.result
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	firewallErr := server.closeFirewallPort()
	return errors.Join(closeErr, serveErr, firewallErr)
}

func (server *kubesprayOfflineServer) closeFirewallPort() error {
	if !server.openedPort {
		return nil
	}
	server.openedPort = false
	err := server.runner.Run(server.cleanupCtx, process.Command{
		Name: server.firewallBin,
		Args: []string{
			"--quiet",
			"--zone=libvirt",
			"--remove-port=" + strconv.Itoa(server.port) + "/tcp",
		},
	})
	if err != nil {
		return fmt.Errorf(
			"close temporary Kubespray offline port %d/tcp: %w",
			server.port,
			err,
		)
	}
	return nil
}

func (server *kubesprayOfflineServer) openFirewallPort(ctx context.Context) error {
	if server.runner == nil {
		return errors.New("Kubespray offline server command runner is unavailable")
	}
	if server.firewallBin == "" {
		return errors.New("validated firewalld preflight identity is required")
	}
	port := strconv.Itoa(server.port) + "/tcp"
	queryErr := server.runner.Run(ctx, process.Command{
		Name: server.firewallBin,
		Args: []string{"--quiet", "--zone=libvirt", "--query-port=" + port},
	})
	if queryErr == nil {
		// A pre-existing rule is not Atum-owned and must not be removed.
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(queryErr, &exitErr) || exitErr.ExitCode() != 1 {
		return fmt.Errorf(
			"query temporary Kubespray offline port %s: %w",
			port,
			queryErr,
		)
	}
	if err := server.runner.Run(ctx, process.Command{
		Name: server.firewallBin,
		Args: []string{"--quiet", "--zone=libvirt", "--add-port=" + port},
	}); err != nil {
		return fmt.Errorf(
			"open temporary Kubespray offline port %s: %w",
			port,
			err,
		)
	}
	server.openedPort = true
	return nil
}

func (service Service) kubesprayOfflineInputs(
	ctx context.Context,
	toolchain Toolchain,
) (map[string]any, *kubesprayOfflineServer, error) {
	var inventory *config.KubesprayArtifactInventory
	for index := range service.Project.Desired.Delivery.Kubespray {
		candidate := &service.Project.Desired.Delivery.Kubespray[index]
		if candidate.KubernetesVersion != toolchain.Release.Kubernetes ||
			candidate.KubesprayCommit != toolchain.Release.Kubespray.Commit {
			continue
		}
		if inventory != nil {
			return nil, nil, fmt.Errorf(
				"Kubespray offline inventory %s/%s is duplicated",
				candidate.KubernetesVersion,
				candidate.KubesprayCommit,
			)
		}
		inventory = candidate
	}
	if inventory == nil {
		return nil, nil, fmt.Errorf(
			"Kubespray offline inventory is absent for %s/%s",
			toolchain.Release.Kubernetes,
			toolchain.Release.Kubespray.Commit,
		)
	}
	receipt, err := delivery.LoadReceipt(service.Project)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"load required Harbor publication receipt: %w",
			err,
		)
	}
	publishedImages, err := validatePublishedKubesprayImages(
		*inventory,
		service.Project.Desired.Delivery.Images,
		receipt.Delivery,
	)
	if err != nil {
		return nil, nil, err
	}
	if err := validateKubesprayOfflineFiles(
		ctx,
		service.Project.Root,
		inventory.Files,
		config.EffectiveWorkLimit(
			0,
			service.Project.Desired.Updates.Parallelism,
			config.DefaultWorkLimit,
		),
	); err != nil {
		return nil, nil, err
	}
	if err := verifyLiveKubesprayImages(
		ctx,
		service.Project.Desired.Delivery.Registry,
		publishedImages,
		config.EffectiveWorkLimit(
			0,
			service.Project.Desired.Updates.Parallelism,
			config.DefaultWorkLimit,
		),
		service.RootCAPEM,
	); err != nil {
		return nil, nil, err
	}
	routes := make(map[string]config.KubesprayFile, len(inventory.Files))
	variables := make(map[string]any, len(inventory.Files))
	for _, file := range inventory.Files {
		route := "/" + strings.TrimPrefix(file.RepositoryPath, "/")
		if _, duplicate := routes[route]; duplicate {
			return nil, nil, fmt.Errorf(
				"Kubespray offline route %s is duplicated",
				route,
			)
		}
		routes[route] = file
	}
	targetName := service.Project.Desired.Infrastructure.Active
	target, found := service.Project.Desired.Infrastructure.Targets[targetName]
	if !found {
		return nil, nil, fmt.Errorf(
			"active infrastructure target %q is absent",
			targetName,
		)
	}
	if target.LocalAccess == nil {
		return nil, nil, fmt.Errorf(
			"active infrastructure target %q has no local access contract",
			targetName,
		)
	}
	offlineHost := target.LocalAccess.DNSServer
	listener, err := (&net.ListenConfig{}).Listen(
		ctx,
		"tcp",
		net.JoinHostPort(offlineHost, "0"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"listen for Kubespray offline files: %w",
			err,
		)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	base := "http://" + net.JoinHostPort(
		offlineHost,
		strconv.Itoa(port),
	)
	for route, file := range routes {
		variables[file.ID+"_download_url"] = base + route
	}
	// Let Kubespray fetch pinned files directly on each node. This is its normal
	// download path and avoids the controller-side rsync cache, whose SSH
	// subprocess is denied by the Fedora SELinux rsync domain. The content-only
	// server is exposed to the libvirt zone for exactly this convergence.
	variables["download_container"] = true
	variables["download_force_cache"] = false
	variables["download_localhost"] = false
	variables["download_run_once"] = false
	handler := &kubesprayOfflineHandler{
		root: service.Project.Root, routes: routes,
	}
	httpServer := &http.Server{Handler: handler}
	running := &kubesprayOfflineServer{
		server:      httpServer,
		listener:    listener,
		result:      make(chan error, 1),
		cleanupCtx:  context.WithoutCancel(ctx),
		firewallBin: service.FirewallBin,
		runner:      service.Runner,
		port:        port,
	}
	if err := running.openFirewallPort(ctx); err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	go func() {
		running.result <- httpServer.Serve(listener)
	}()
	return variables, running, nil
}

func validatePublishedKubesprayImages(
	inventory config.KubesprayArtifactInventory,
	desired []config.Image,
	lock config.ImageLock,
) ([]config.LockedImage, error) {
	desiredByID := make(map[string]config.Image, len(desired))
	for _, image := range desired {
		if _, duplicate := desiredByID[image.ID]; duplicate {
			return nil, fmt.Errorf("desired image %s is duplicated", image.ID)
		}
		desiredByID[image.ID] = image
	}
	lockedByID := make(map[string]config.LockedImage, len(lock.Images))
	for _, image := range lock.Images {
		if _, duplicate := lockedByID[image.ID]; duplicate {
			return nil, fmt.Errorf("published image %s is duplicated", image.ID)
		}
		lockedByID[image.ID] = image
	}
	selected := make([]config.LockedImage, 0, len(inventory.Images))
	selectedIDs := make(map[string]struct{}, len(inventory.Images))
	selectedTargets := make(map[string]string, len(inventory.Images))
	for _, id := range inventory.Images {
		if _, duplicate := selectedIDs[id]; duplicate {
			return nil, fmt.Errorf("Kubespray image %s is selected more than once", id)
		}
		selectedIDs[id] = struct{}{}
		wanted, found := desiredByID[id]
		if !found {
			return nil, fmt.Errorf("Kubespray image %s is absent from desired state", id)
		}
		published, found := lockedByID[id]
		if !found ||
			published.Target != wanted.Target ||
			published.Digest != wanted.Delivery.Default.Digest ||
			published.Delivery.Type != "mirror" ||
			published.Delivery.Source != wanted.Delivery.Default.Source {
			return nil, fmt.Errorf(
				"Kubespray image %s is not published at its exact Harbor target",
				id,
			)
		}
		if current, duplicate := selectedTargets[published.Target]; duplicate {
			return nil, fmt.Errorf(
				"Kubespray images %s and %s share Harbor target %s",
				current,
				id,
				published.Target,
			)
		}
		selectedTargets[published.Target] = id
		selected = append(selected, published)
	}
	return selected, nil
}

func verifyLiveKubesprayImages(
	ctx context.Context,
	registry config.Registry,
	images []config.LockedImage,
	parallelism int,
	rootCAPEM []byte,
) error {
	if len(images) == 0 {
		return errors.New("Kubespray has no receipt-bound Harbor images")
	}
	client, err := atumoci.NewClient(registry, atumoci.Credentials{
		CACert: rootCAPEM,
	})
	if err != nil {
		return fmt.Errorf("open Harbor observer for Kubespray admission: %w", err)
	}
	defer client.Clear()
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism,
		0,
		config.DefaultWorkLimit,
	))
	for index := range images {
		image := images[index]
		group.Go(func() error {
			descriptor, err := client.Resolve(groupContext, image.Target)
			if err != nil {
				return fmt.Errorf(
					"resolve required Kubespray image %s from Harbor: %w",
					image.ID,
					err,
				)
			}
			if descriptor.Digest.String() != image.Digest {
				return fmt.Errorf(
					"Kubespray image %s resolves to %s, want receipt digest %s",
					image.ID,
					descriptor.Digest,
					image.Digest,
				)
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return fmt.Errorf("verify live Kubespray Harbor admission: %w", err)
	}
	return nil
}

func validateKubesprayOfflineFiles(
	ctx context.Context,
	root string,
	files []config.KubesprayFile,
	parallelism int,
) error {
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(config.EffectiveWorkLimit(
		parallelism, 0, config.DefaultWorkLimit,
	))
	for index := range files {
		file := files[index]
		group.Go(func() error {
			input, err := fssecure.OpenRegular(root, file.CacheFile)
			if err != nil {
				return fmt.Errorf(
					"open Kubespray offline file %s: %w",
					file.ID,
					err,
				)
			}
			hash := sha256.New()
			size, readErr := io.Copy(hash, input)
			closeErr := input.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err := groupContext.Err(); err != nil {
				return err
			}
			if size != file.Size ||
				hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
				return fmt.Errorf(
					"Kubespray offline file %s is stale or corrupt",
					file.ID,
				)
			}
			return nil
		})
	}
	return group.Wait()
}

type kubesprayOfflineHandler struct {
	root   string
	routes map[string]config.KubesprayFile
}

func (handler *kubesprayOfflineHandler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, found := handler.routes[request.URL.Path]
	if !found {
		http.NotFound(writer, request)
		return
	}
	input, err := fssecure.OpenRegular(handler.root, file.CacheFile)
	if err != nil {
		http.Error(writer, "offline artifact unavailable", http.StatusNotFound)
		return
	}
	defer input.Close()
	writer.Header().Set("Content-Length", strconv.FormatInt(file.Size, 10))
	writer.Header().Set("ETag", `"`+file.SHA256+`"`)
	writer.Header().Set("Content-Type", "application/octet-stream")
	if request.Method == http.MethodHead {
		writer.WriteHeader(http.StatusOK)
		return
	}
	if _, err := io.CopyN(writer, input, file.Size); err != nil {
		return
	}
}
