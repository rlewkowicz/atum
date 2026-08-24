// Package kube provides bounded, read-only Kubernetes observations. Mutation
// belongs to Terraform, Kubespray/Ansible, or Flux rather than this package.
package kube

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var ErrKubeconfigAbsent = errors.New("cluster kubeconfig is absent")

const kubeconfigLimit = 4 << 20

// Observer owns the private client-go transports used by the narrow
// projections in resources.go. Callers cannot reach mutation-capable clients.
type Observer struct {
	core    kubernetes.Interface
	dynamic dynamic.Interface
}

func New(kubeconfig string) (*Observer, error) {
	if strings.ContainsRune(kubeconfig, os.PathListSeparator) {
		return nil, errors.New("KUBECONFIG must identify one exact cluster file")
	}
	absolute, err := filepath.Abs(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("resolve cluster kubeconfig: %w", err)
	}
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKubeconfigAbsent
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		if err != nil {
			return nil, fmt.Errorf("inspect cluster kubeconfig %s: %w", absolute, err)
		}
		return nil, fmt.Errorf("cluster kubeconfig %s is not a real regular file", absolute)
	}
	if info.Size() <= 0 || info.Size() > kubeconfigLimit {
		return nil, fmt.Errorf("cluster kubeconfig %s has invalid size %d", absolute, info.Size())
	}
	opened, err := os.OpenFile(absolute, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open cluster kubeconfig %s: %w", absolute, err)
	}
	openedInfo, statErr := opened.Stat()
	var data []byte
	var readErr error
	if statErr == nil {
		data, readErr = io.ReadAll(io.LimitReader(opened, kubeconfigLimit+1))
	}
	afterInfo, afterStatErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || readErr != nil || afterStatErr != nil || closeErr != nil ||
		!openedInfo.Mode().IsRegular() || !afterInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) || !os.SameFile(openedInfo, afterInfo) ||
		openedInfo.Size() != afterInfo.Size() || !openedInfo.ModTime().Equal(afterInfo.ModTime()) ||
		int64(len(data)) != afterInfo.Size() || len(data) > kubeconfigLimit {
		return nil, errors.Join(
			fmt.Errorf("cluster kubeconfig %s changed while it was read", absolute),
			statErr, readErr, afterStatErr, closeErr,
		)
	}
	raw, err := clientcmd.Load(data)
	if err != nil {
		return nil, fmt.Errorf("decode cluster kubeconfig: %w", err)
	}
	config, err := clientcmd.NewDefaultClientConfig(*raw, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load cluster kubeconfig: %w", err)
	}
	config = rest.CopyConfig(config)
	config.Timeout = 30 * time.Second
	core, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes observer: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes resource observer: %w", err)
	}
	return &Observer{core: core, dynamic: dynamicClient}, nil
}
