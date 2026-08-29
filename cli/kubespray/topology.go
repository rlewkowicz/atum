package kubespray

import (
	"strconv"
	"strings"
)

var localNodeGroups = [...]string{
	"kube_control_plane",
	"etcd",
	"kube_node",
	"k8s_cluster",
}

// LocalNodeGroups returns the one canonical Kubespray group membership for
// every node in the supported local all-in-one topology.
func LocalNodeGroups() [4]string {
	return localNodeGroups
}

// WriteLocalGroups writes the canonical group graph beneath an existing
// "children" mapping. writeHosts owns the representation of each base group's
// host membership.
func WriteLocalGroups(
	builder *strings.Builder,
	writeHosts func(*strings.Builder, string),
) {
	for _, group := range localNodeGroups[:3] {
		builder.WriteString("    ")
		builder.WriteString(group)
		builder.WriteString(":\n")
		builder.WriteString("      hosts:\n")
		writeHosts(builder, group)
	}
	builder.WriteString("    k8s_cluster:\n")
	builder.WriteString("      children:\n")
	builder.WriteString("        kube_control_plane: {}\n")
	builder.WriteString("        kube_node: {}\n")
}

// SelectionInventory returns the minimal inventory used to evaluate pinned
// Kubespray variables. Its one synthetic node has the same memberships as
// every supported runtime node.
func SelectionInventory() []byte {
	var builder strings.Builder
	builder.Grow(512)
	builder.WriteString("---\nall:\n")
	builder.WriteString("  hosts:\n")
	builder.WriteString("    atum-selection:\n")
	builder.WriteString("      ansible_connection: local\n")
	builder.WriteString("      ansible_host: 127.0.0.1\n")
	builder.WriteString("      ip: 127.0.0.1\n")
	builder.WriteString("      access_ip: 127.0.0.1\n")
	builder.WriteString("      ansible_system: Linux\n")
	builder.WriteString("      ansible_architecture: x86_64\n")
	builder.WriteString("      host_architecture: amd64\n")
	builder.WriteString("      etcd_member_name: atum-selection\n")
	builder.WriteString("  children:\n")
	WriteLocalGroups(&builder, func(builder *strings.Builder, _ string) {
		builder.WriteString("        ")
		builder.WriteString(strconv.Quote("atum-selection"))
		builder.WriteString(": {}\n")
	})
	return []byte(builder.String())
}
