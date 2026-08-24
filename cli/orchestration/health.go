package orchestration

import (
	"context"
	"fmt"
	"time"

	"atum/cli/kube"
	"atum/cli/progress"

	"k8s.io/apimachinery/pkg/util/wait"
)

const healthTimeout = 15 * time.Minute

func (service Service) waitHealthy(ctx context.Context, client *clusterClient, exactVersion string) error {
	id := "kubernetes:" + exactVersion
	label := "Kubernetes " + exactVersion
	progress.Start(ctx, progress.Orchestration, id, label, "checking cluster health")
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, healthTimeout, true, func(ctx context.Context) (bool, error) {
		version, err := client.ServerVersion(ctx)
		if err != nil {
			progress.Update(ctx, progress.Orchestration, id, label, "waiting for API server", 0, 0)
			return false, nil
		}
		actual, err := canonicalKubernetesVersion(version)
		if err != nil || actual != exactVersion {
			progress.Update(ctx, progress.Orchestration, id, label, "API reports "+version, 0, 0)
			return false, nil
		}
		nodes, err := client.Nodes(ctx)
		if err != nil || len(nodes) == 0 {
			progress.Update(ctx, progress.Orchestration, id, label, "waiting for nodes", 0, 0)
			return false, nil
		}
		readyNodes := 0
		for _, node := range nodes {
			id := "node:" + node.Name
			label := "Node " + node.Name
			kubeletVersion, err := canonicalKubernetesVersion(node.KubeletVersion)
			switch {
			case node.Unschedulable:
				progress.Update(ctx, progress.Orchestration, id, label, "cordoned; waiting for uncordon", 0, 0)
			case !node.Ready:
				progress.Update(ctx, progress.Orchestration, id, label, "waiting for Ready", 0, 0)
			case err != nil || kubeletVersion != exactVersion:
				progress.Update(ctx, progress.Orchestration, id, label,
					fmt.Sprintf("kubelet %s; want %s", node.KubeletVersion, exactVersion), 0, 0)
			default:
				readyNodes++
				progress.Done(ctx, progress.Orchestration, id, label, "Ready · kubelet "+kubeletVersion)
			}
		}
		if readyNodes != len(nodes) {
			progress.Update(ctx, progress.Orchestration, id, label, "nodes ready", readyNodes, len(nodes))
			return false, nil
		}
		progress.Update(ctx, progress.Orchestration, id, label, "system pods converging", readyNodes, len(nodes))
		continuation := ""
		observedPods := 0
		for {
			page, err := client.ListPods(ctx, "kube-system", kube.ListOptions{Limit: 500, Continue: continuation})
			if err != nil {
				return false, nil
			}
			observedPods += len(page.Items)
			for _, pod := range page.Items {
				if pod.Deleting || pod.Failed() || (!pod.Succeeded() && !pod.Ready) {
					return false, nil
				}
			}
			continuation = page.Continue
			if continuation == "" {
				break
			}
		}
		if observedPods == 0 {
			return false, nil
		}
		progress.Done(ctx, progress.Orchestration, id, label, fmt.Sprintf("%d/%d nodes healthy", readyNodes, len(nodes)))
		return true, nil
	})
	if err != nil {
		progress.Fail(ctx, progress.Orchestration, id, label, err)
	}
	return err
}
