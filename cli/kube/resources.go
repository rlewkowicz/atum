package kube

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	pageLimit             int64 = 500
	maxContinuation             = 16 << 10
	maxNodes                    = 4096
	maxResources                = 20_000
	maxServiceIngresses         = 32
	maxTLSCertificateSize       = 1 << 20
)

type Resource uint8

const (
	GitRepository Resource = iota + 1
	Kustomization
	OCIRepository
	HelmRelease
	Certificate
	PlatformIdentityConfiguration
)

type ListOptions struct {
	LabelSelector string
	Continue      string
	Limit         int64
}

// Object is a detached, read-only resource projection. Object contains the
// API response payload for exact Flux contract inspection; mutating it cannot
// mutate the cluster.
type Object struct {
	Object            map[string]any
	Name              string
	Namespace         string
	Labels            map[string]string
	Generation        int64
	DeletionTimestamp *metav1.Time
	Ready             bool
}

func (object *Object) GetName() string                    { return object.Name }
func (object *Object) GetNamespace() string               { return object.Namespace }
func (object *Object) GetLabels() map[string]string       { return object.Labels }
func (object *Object) GetGeneration() int64               { return object.Generation }
func (object *Object) GetDeletionTimestamp() *metav1.Time { return object.DeletionTimestamp }
func IsReady(object *Object) bool                         { return object != nil && object.Ready }

type ObjectPage struct {
	Items    []Object
	Continue string
}

func (page ObjectPage) GetContinue() string { return page.Continue }

type PodContainer struct {
	Name    string
	Image   string
	ImageID string
}

type Pod struct {
	Name       string
	Namespace  string
	Labels     map[string]string
	Phase      corev1.PodPhase
	Deleting   bool
	Ready      bool
	Containers []PodContainer
}

func (pod Pod) Terminal() bool {
	return pod.Phase == corev1.PodSucceeded || pod.Phase == corev1.PodFailed
}

func (pod Pod) Succeeded() bool { return pod.Phase == corev1.PodSucceeded }
func (pod Pod) Failed() bool    { return pod.Phase == corev1.PodFailed }

type PodPage struct {
	Items    []Pod
	Continue string
}

type Node struct {
	Name           string
	Unschedulable  bool
	KubeletVersion string
	Ready          bool
	ControlPlane   bool
}

func (observer *Observer) ServerVersion(ctx context.Context) (string, error) {
	version, err := observer.core.Discovery().ServerVersion()
	if err != nil {
		return "", err
	}
	return version.GitVersion, nil
}

func (observer *Observer) ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, bool, error) {
	object, err := observer.core.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if object.DeletionTimestamp != nil {
		return nil, false, nil
	}
	data := make(map[string]string, len(object.Data))
	for key, value := range object.Data {
		data[key] = value
	}
	return data, true, nil
}

// SecretValue returns one bounded detached Secret value. Every byte slice
// received from the API is cleared before return; values other than the
// selected key are cleared before the selected value is copied.
func (observer *Observer) SecretValue(
	ctx context.Context,
	namespace, name, key string,
) ([]byte, bool, error) {
	if key == "" {
		return nil, false, errors.New("Secret value key is required")
	}
	var selected []byte
	secretFound, err := observer.observeSecret(ctx, namespace, name, func(object *corev1.Secret) error {
		value, valueFound := object.Data[key]
		for receivedKey, received := range object.Data {
			if receivedKey == key {
				continue
			}
			clear(received)
			delete(object.Data, receivedKey)
		}
		if !valueFound || len(value) == 0 {
			return nil
		}
		if len(value) > maxTLSCertificateSize {
			return fmt.Errorf("Secret %s/%s value %q exceeds %d bytes",
				namespace, name, key, maxTLSCertificateSize)
		}
		selected = append([]byte(nil), value...)
		return nil
	})
	return selected, secretFound && len(selected) != 0, err
}

func (observer *Observer) observeSecret(
	ctx context.Context,
	namespace, name string,
	project func(*corev1.Secret) error,
) (bool, error) {
	object, err := observer.core.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer clearSecretData(object.Data)
	if object.DeletionTimestamp != nil {
		return false, nil
	}
	return true, project(object)
}

func clearSecretData(data map[string][]byte) {
	for key, value := range data {
		clear(value)
		delete(data, key)
	}
}

// ServiceIngressIPs returns a bounded copy of the IP addresses published in a
// Service's load-balancer status. Hostname entries remain intentionally
// excluded because callers use this projection to verify literal VIPs.
func (observer *Observer) ServiceIngressIPs(ctx context.Context, namespace, name string) ([]string, bool, error) {
	object, err := observer.core.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if object.DeletionTimestamp != nil {
		return nil, false, nil
	}
	ingress := object.Status.LoadBalancer.Ingress
	if len(ingress) > maxServiceIngresses {
		return nil, false, fmt.Errorf("Service %s/%s has more than %d load-balancer ingress entries",
			namespace, name, maxServiceIngresses)
	}
	ips := make([]string, 0, len(ingress))
	for i := range ingress {
		if ingress[i].IP != "" {
			ips = append(ips, ingress[i].IP)
		}
	}
	return ips, true, nil
}

func (observer *Observer) GetResource(ctx context.Context, resource Resource, namespace, name string) (*Object, bool, error) {
	gvr, err := resourceGVR(resource)
	if err != nil {
		return nil, false, err
	}
	item, err := observer.dynamic.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	projected := projectObject(item)
	return &projected, true, nil
}

func (observer *Observer) ListResources(ctx context.Context, resource Resource, namespace string, options ListOptions) (ObjectPage, error) {
	if err := validateListOptions(options); err != nil {
		return ObjectPage{}, err
	}
	gvr, err := resourceGVR(resource)
	if err != nil {
		return ObjectPage{}, err
	}
	page, err := observer.dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: options.LabelSelector,
		Continue:      options.Continue,
		Limit:         listLimit(options.Limit),
	})
	if err != nil {
		return ObjectPage{}, err
	}
	items := make([]Object, len(page.Items))
	for index := range page.Items {
		items[index] = projectObject(&page.Items[index])
	}
	return ObjectPage{Items: items, Continue: page.GetContinue()}, nil
}

// Resources collects a bounded complete resource set using fixed-size API
// pages. Exact source verification needs set-wide duplicate and omission
// checks, while the cap prevents an untrusted API response from growing memory
// without limit.
func (observer *Observer) Resources(ctx context.Context, resource Resource, namespace, labelSelector string) ([]Object, error) {
	items := make([]Object, 0, pageLimit)
	continuation := ""
	for {
		page, err := observer.ListResources(ctx, resource, namespace, ListOptions{
			LabelSelector: labelSelector, Continue: continuation, Limit: pageLimit,
		})
		if err != nil {
			return nil, err
		}
		if len(items)+len(page.Items) > maxResources {
			return nil, fmt.Errorf("observed resource count exceeds %d", maxResources)
		}
		items = append(items, page.Items...)
		continuation = page.Continue
		if continuation == "" {
			return items, nil
		}
	}
}

func (observer *Observer) ListPods(ctx context.Context, namespace string, options ListOptions) (PodPage, error) {
	if err := validateListOptions(options); err != nil {
		return PodPage{}, err
	}
	page, err := observer.core.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: options.LabelSelector,
		Continue:      options.Continue,
		Limit:         listLimit(options.Limit),
	})
	if err != nil {
		return PodPage{}, err
	}
	items := make([]Pod, len(page.Items))
	for index := range page.Items {
		items[index] = projectPod(&page.Items[index])
	}
	return PodPage{Items: items, Continue: page.Continue}, nil
}

// Pods collects one bounded complete pod set for a read-only observation
// round. Keeping pagination here gives every caller the same memory cap.
func (observer *Observer) Pods(
	ctx context.Context,
	namespace, labelSelector string,
) ([]Pod, error) {
	items := make([]Pod, 0, pageLimit)
	continuation := ""
	for {
		page, err := observer.ListPods(ctx, namespace, ListOptions{
			LabelSelector: labelSelector, Continue: continuation, Limit: pageLimit,
		})
		if err != nil {
			return nil, err
		}
		if len(items)+len(page.Items) > maxResources {
			return nil, fmt.Errorf("observed pod count exceeds %d", maxResources)
		}
		items = append(items, page.Items...)
		continuation = page.Continue
		if continuation == "" {
			return items, nil
		}
	}
}

func (observer *Observer) Nodes(ctx context.Context) ([]Node, error) {
	result := make([]Node, 0, 8)
	continuation := ""
	for {
		page, err := observer.core.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: pageLimit, Continue: continuation})
		if err != nil {
			return nil, err
		}
		if len(result)+len(page.Items) > maxNodes {
			return nil, fmt.Errorf("cluster node count exceeds %d", maxNodes)
		}
		for index := range page.Items {
			item := &page.Items[index]
			ready := false
			for _, condition := range item.Status.Conditions {
				if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			result = append(result, Node{
				Name: item.Name, Unschedulable: item.Spec.Unschedulable,
				KubeletVersion: item.Status.NodeInfo.KubeletVersion, Ready: ready,
				ControlPlane: nodeHasControlPlaneRole(item.Labels),
			})
		}
		continuation = page.Continue
		if continuation == "" {
			return result, nil
		}
	}
}

func nodeHasControlPlaneRole(labels map[string]string) bool {
	if labels == nil {
		return false
	}
	_, controlPlane := labels["node-role.kubernetes.io/control-plane"]
	_, legacyMaster := labels["node-role.kubernetes.io/master"]
	return controlPlane || legacyMaster
}

func resourceGVR(resource Resource) (schema.GroupVersionResource, error) {
	switch resource {
	case GitRepository:
		return schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}, nil
	case Kustomization:
		return schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}, nil
	case OCIRepository:
		return schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "ocirepositories"}, nil
	case HelmRelease:
		return schema.GroupVersionResource{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}, nil
	case Certificate:
		return schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}, nil
	case PlatformIdentityConfiguration:
		return schema.GroupVersionResource{Group: "platform.atum.dev", Version: "v1alpha1", Resource: "platformidentityconfigurations"}, nil
	default:
		return schema.GroupVersionResource{}, fmt.Errorf("unsupported observed resource %d", resource)
	}
}

func validateListOptions(options ListOptions) error {
	if options.Limit < 0 || options.Limit > pageLimit {
		return fmt.Errorf("Kubernetes observation page limit must be between 1 and %d", pageLimit)
	}
	if len(options.Continue) > maxContinuation {
		return errors.New("Kubernetes continuation token exceeds 16 KiB")
	}
	return nil
}

func listLimit(limit int64) int64 {
	if limit == 0 {
		return pageLimit
	}
	return limit
}

func projectObject(item *unstructured.Unstructured) Object {
	return Object{
		Object: item.Object, Name: item.GetName(), Namespace: item.GetNamespace(),
		Labels: item.GetLabels(), Generation: item.GetGeneration(),
		DeletionTimestamp: item.GetDeletionTimestamp(), Ready: objectReady(item),
	}
}

func objectReady(object *unstructured.Unstructured) bool {
	if object.GetDeletionTimestamp() != nil {
		return false
	}
	statusObserved, statusFound, statusErr := unstructured.NestedInt64(object.Object, "status", "observedGeneration")
	if statusErr != nil || (statusFound && statusObserved != object.GetGeneration()) {
		return false
	}
	conditions, found, err := unstructured.NestedSlice(object.Object, "status", "conditions")
	if err != nil || !found {
		return false
	}
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok || condition["status"] != "True" {
			continue
		}
		if condition["type"] != "Ready" {
			continue
		}
		observed, present := condition["observedGeneration"]
		if !present {
			return true
		}
		switch value := observed.(type) {
		case int64:
			return value == object.GetGeneration()
		case float64:
			return int64(value) == object.GetGeneration()
		default:
			return false
		}
	}
	return false
}

func projectPod(item *corev1.Pod) Pod {
	statuses := make(map[string]string,
		len(item.Status.InitContainerStatuses)+len(item.Status.ContainerStatuses)+len(item.Status.EphemeralContainerStatuses))
	for _, status := range item.Status.InitContainerStatuses {
		statuses[status.Name] = status.ImageID
	}
	for _, status := range item.Status.ContainerStatuses {
		statuses[status.Name] = status.ImageID
	}
	for _, status := range item.Status.EphemeralContainerStatuses {
		statuses[status.Name] = status.ImageID
	}
	containers := make([]PodContainer, 0,
		len(item.Spec.InitContainers)+len(item.Spec.Containers)+len(item.Spec.EphemeralContainers))
	for _, container := range item.Spec.InitContainers {
		containers = append(containers, PodContainer{Name: container.Name, Image: container.Image, ImageID: statuses[container.Name]})
	}
	for _, container := range item.Spec.Containers {
		containers = append(containers, PodContainer{Name: container.Name, Image: container.Image, ImageID: statuses[container.Name]})
	}
	for _, container := range item.Spec.EphemeralContainers {
		containers = append(containers, PodContainer{Name: container.Name, Image: container.Image, ImageID: statuses[container.Name]})
	}
	ready := false
	if item.Status.Phase == corev1.PodRunning {
		for _, condition := range item.Status.Conditions {
			if condition.Type == corev1.PodReady {
				ready = condition.Status == corev1.ConditionTrue
				break
			}
		}
	}
	labels := make(map[string]string, len(item.Labels))
	for key, value := range item.Labels {
		labels[key] = value
	}
	return Pod{
		Name: item.Name, Namespace: item.Namespace, Labels: labels,
		Phase: item.Status.Phase, Deleting: item.DeletionTimestamp != nil,
		Ready: ready, Containers: containers,
	}
}
