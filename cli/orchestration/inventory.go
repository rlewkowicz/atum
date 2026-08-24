package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"atum/cli/fssecure"
	"atum/cli/process"

	"k8s.io/apimachinery/pkg/util/validation"
)

type terraformOutputValue[T any] struct {
	Value T `json:"value"`
}

type terraformInventoryOutputs struct {
	NodeLabels        terraformOutputValue[[]string] `json:"node_labels"`
	NodeMainIPs       terraformOutputValue[[]string] `json:"node_main_ips"`
	NodeInternalIPs   terraformOutputValue[[]string] `json:"node_internal_ips"`
	LoadBalancerIPv4  terraformOutputValue[string]   `json:"load_balancer_ipv4"`
	BastionLabel      *terraformOutputValue[string]  `json:"bastion_label"`
	BastionMainIP     *terraformOutputValue[string]  `json:"bastion_main_ip"`
	BastionInternalIP *terraformOutputValue[string]  `json:"bastion_internal_ip"`
}

type clusterInventory struct {
	LoadBalancerAddress string
	AnsibleUser         string
	Bastion             *clusterInventoryBastion
	Hosts               []clusterInventoryHost
}

type clusterInventoryBastion struct {
	Name        string
	AnsibleHost string
	IP          string
}

type clusterInventoryHost struct {
	Name           string
	AnsibleHost    string
	IP             string
	AccessIP       string
	EtcdMemberName string
}

type InventoryService struct {
	OutputRunner process.OutputRunner
	Root         string
	TerraformBin string
	TerraformDir string
	Environment  []string
	AnsibleUser  string
}

func (s InventoryService) Generate(ctx context.Context, inventoryPath string) error {
	output, err := s.readTerraformInventoryOutput(ctx)
	if err != nil {
		return err
	}

	inventory, err := parseTerraformInventory(output)
	if err != nil {
		return err
	}
	inventory.AnsibleUser, err = validAnsibleUser(s.AnsibleUser)
	if err != nil {
		return err
	}

	return fssecure.WriteRegular(s.Root, inventoryPath, renderInventoryYAML(inventory), 0o600)
}

func (s InventoryService) readTerraformInventoryOutput(ctx context.Context) ([]byte, error) {
	if s.OutputRunner == nil {
		return nil, errors.New("terraform output capture requires an output runner")
	}
	if s.TerraformBin == "" {
		return nil, errors.New("validated Terraform preflight identity is required")
	}

	command := process.Command{
		Name: s.TerraformBin,
		Args: []string{"-chdir=" + s.TerraformDir, "output", "-json"},
		Dir:  s.Root,
		Env:  s.Environment,
	}
	output, err := s.OutputRunner.Output(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("%s output failed: %w", command.Name, err)
	}
	return output, nil
}

func parseTerraformInventory(data []byte) (clusterInventory, error) {
	var outputs terraformInventoryOutputs
	if err := json.Unmarshal(data, &outputs); err != nil {
		return clusterInventory{}, fmt.Errorf("parse terraform output JSON: %w", err)
	}

	labels := outputs.NodeLabels.Value
	mainIPs := outputs.NodeMainIPs.Value
	internalIPs := outputs.NodeInternalIPs.Value
	loadBalancerAddress, err := inventoryIPv4("load_balancer_ipv4", outputs.LoadBalancerIPv4.Value)
	if len(labels) == 0 {
		return clusterInventory{}, errors.New("terraform output node_labels must contain at least one node")
	}
	if len(internalIPs) != len(labels) {
		return clusterInventory{}, fmt.Errorf("terraform output node_internal_ips length %d does not match node_labels length %d", len(internalIPs), len(labels))
	}
	if len(mainIPs) > 0 && len(mainIPs) != len(labels) {
		return clusterInventory{}, fmt.Errorf("terraform output node_main_ips length %d does not match node_labels length %d", len(mainIPs), len(labels))
	}
	if err != nil {
		return clusterInventory{}, err
	}

	bastion, err := parseTerraformBastion(outputs)
	if err != nil {
		return clusterInventory{}, err
	}

	seen := make(map[string]struct{}, len(labels))
	hosts := make([]clusterInventoryHost, len(labels))
	for i, label := range labels {
		name := strings.TrimSpace(label)
		if name == "" {
			return clusterInventory{}, fmt.Errorf("terraform output node_labels[%d] must be set", i)
		}
		if problems := validation.IsDNS1123Subdomain(name); len(problems) != 0 {
			return clusterInventory{}, fmt.Errorf("terraform output node_labels[%d] is not a Kubernetes node name: %s", i, strings.Join(problems, "; "))
		}
		if _, exists := seen[name]; exists {
			return clusterInventory{}, fmt.Errorf("terraform output node_labels[%d] duplicates host %q", i, name)
		}
		seen[name] = struct{}{}

		internalIP, err := inventoryIPv4(fmt.Sprintf("node_internal_ips[%d]", i), internalIPs[i])
		if err != nil {
			return clusterInventory{}, err
		}
		ansibleHost := internalIP
		if bastion == nil && len(mainIPs) > 0 {
			if strings.TrimSpace(mainIPs[i]) != "" {
				mainIP, err := inventoryIPv4(fmt.Sprintf("node_main_ips[%d]", i), mainIPs[i])
				if err != nil {
					return clusterInventory{}, err
				}
				ansibleHost = mainIP
			}
		}

		hosts[i] = clusterInventoryHost{
			Name:           name,
			AnsibleHost:    ansibleHost,
			IP:             internalIP,
			AccessIP:       internalIP,
			EtcdMemberName: name,
		}
	}

	return clusterInventory{
		LoadBalancerAddress: loadBalancerAddress,
		Bastion:             bastion,
		Hosts:               hosts,
	}, nil
}

func parseTerraformBastion(outputs terraformInventoryOutputs) (*clusterInventoryBastion, error) {
	name := optionalTerraformString(outputs.BastionLabel)
	mainIP := optionalTerraformString(outputs.BastionMainIP)
	internalIP := optionalTerraformString(outputs.BastionInternalIP)
	if mainIP == "" && internalIP == "" {
		return nil, nil
	}
	if mainIP == "" {
		return nil, errors.New("terraform output bastion_main_ip must be set when bastion outputs are present")
	}
	var err error
	mainIP, err = inventoryIPv4("bastion_main_ip", mainIP)
	if err != nil {
		return nil, err
	}
	if internalIP == "" {
		internalIP = mainIP
	} else if internalIP, err = inventoryIPv4("bastion_internal_ip", internalIP); err != nil {
		return nil, err
	}
	if name == "" {
		name = "bastion-host"
	}
	return &clusterInventoryBastion{
		Name:        name,
		AnsibleHost: mainIP,
		IP:          internalIP,
	}, nil
}

func optionalTerraformString(output *terraformOutputValue[string]) string {
	if output == nil {
		return ""
	}
	return strings.TrimSpace(output.Value)
}

func inventoryIPv4(field, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return "", fmt.Errorf("terraform output %s must be an IPv4 address", field)
	}
	return address.String(), nil
}

func validAnsibleUser(raw string) (string, error) {
	user := strings.TrimSpace(raw)
	if user == "" {
		return "", nil
	}
	if user[0] == '-' {
		return "", errors.New("Ansible user cannot begin with a dash")
	}
	for _, character := range user {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			return "", fmt.Errorf("Ansible user %q contains unsupported characters", user)
		}
	}
	return user, nil
}

func renderInventoryYAML(inventory clusterInventory) []byte {
	var builder strings.Builder
	builder.Grow(512 + len(inventory.Hosts)*320)

	builder.WriteString("---\nall:\n")
	builder.WriteString("  vars:\n")
	writeYAMLScalar(&builder, 4, "atum_load_balancer_address", inventory.LoadBalancerAddress)
	if inventory.AnsibleUser != "" {
		writeYAMLScalar(&builder, 4, "ansible_user", inventory.AnsibleUser)
	}
	builder.WriteString("  hosts:\n")
	for _, host := range inventory.Hosts {
		writeYAMLKey(&builder, 4, host.Name)
		writeYAMLScalar(&builder, 6, "ansible_host", host.AnsibleHost)
		writeYAMLScalar(&builder, 6, "ip", host.IP)
		writeYAMLScalar(&builder, 6, "access_ip", host.AccessIP)
		writeYAMLScalar(&builder, 6, "etcd_member_name", host.EtcdMemberName)
		if inventory.Bastion != nil {
			writeYAMLScalar(&builder, 6, "ansible_ssh_common_args", inventory.bastionSSHCommonArgs())
		}
	}
	builder.WriteString("  children:\n")
	writeInventoryGroup(&builder, "kube_control_plane", inventory.Hosts)
	writeInventoryGroup(&builder, "etcd", inventory.Hosts)
	writeInventoryGroup(&builder, "kube_node", inventory.Hosts)
	builder.WriteString("    k8s_cluster:\n")
	builder.WriteString("      children:\n")
	builder.WriteString("        kube_control_plane: {}\n")
	builder.WriteString("        kube_node: {}\n")
	return []byte(builder.String())
}

func (inventory clusterInventory) bastionSSHCommonArgs() string {
	user := inventory.AnsibleUser
	if user == "" {
		user = "root"
	}
	return fmt.Sprintf("-o ProxyCommand='ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %%h:%%p -q {%% if ansible_ssh_private_key_file is defined %%}-i {{ ansible_ssh_private_key_file }} {%% endif %%}%s@%s'", user, inventory.Bastion.AnsibleHost)
}

func writeInventoryGroup(builder *strings.Builder, name string, hosts []clusterInventoryHost) {
	builder.WriteString("    ")
	builder.WriteString(name)
	builder.WriteString(":\n")
	builder.WriteString("      hosts:\n")
	for _, host := range hosts {
		builder.WriteString("        ")
		builder.WriteString(strconv.Quote(host.Name))
		builder.WriteString(": {}\n")
	}
}

func writeYAMLScalar(builder *strings.Builder, indent int, key, value string) {
	writeIndent(builder, indent)
	builder.WriteString(key)
	builder.WriteString(": ")
	builder.WriteString(strconv.Quote(value))
	builder.WriteByte('\n')
}

func writeYAMLKey(builder *strings.Builder, indent int, key string) {
	writeIndent(builder, indent)
	builder.WriteString(strconv.Quote(key))
	builder.WriteString(":\n")
}

func writeIndent(builder *strings.Builder, indent int) {
	for range indent {
		builder.WriteByte(' ')
	}
}
