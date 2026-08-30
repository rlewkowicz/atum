package orchestration

import (
	"strings"
	"testing"
)

func TestLocalInventoryUsesDirectNodeConnections(t *testing.T) {
	t.Parallel()

	inventory, err := parseTerraformInventory([]byte(`{
		"node_labels":{"value":["atum-node-1"]},
		"node_main_ips":{"value":["10.77.0.11"]},
		"node_internal_ips":{"value":["10.77.0.11"]},
		"load_balancer_ipv4":{"value":"10.77.0.10"},
		"dns_server":{"value":"10.77.0.1"},
		"bastion_label":{"value":"atum-bastion"},
		"bastion_main_ip":{"value":"10.77.0.9"},
		"bastion_internal_ip":{"value":"10.77.0.9"}
	}`))
	if err != nil {
		t.Fatalf("parse inventory: %v", err)
	}
	if inventory.Hosts[0].AnsibleHost != "10.77.0.11" {
		t.Fatalf("ansible host = %q, want direct node address", inventory.Hosts[0].AnsibleHost)
	}
	if inventory.Hosts[0].ProxyViaBastion {
		t.Fatal("local node connection unexpectedly uses the bastion")
	}
	if strings.Contains(string(renderInventoryYAML(inventory)), "ProxyCommand") {
		t.Fatal("local inventory contains a proxy command")
	}
}

func TestRemoteInventoryUsesBastionForInternalNodeConnections(t *testing.T) {
	t.Parallel()

	inventory, err := parseTerraformInventory([]byte(`{
		"node_labels":{"value":["atum-node-1"]},
		"node_main_ips":{"value":["198.51.100.11"]},
		"node_internal_ips":{"value":["10.77.0.11"]},
		"load_balancer_ipv4":{"value":"198.51.100.10"},
		"dns_server":{"value":"10.77.0.1"},
		"bastion_label":{"value":"atum-bastion"},
		"bastion_main_ip":{"value":"198.51.100.9"},
		"bastion_internal_ip":{"value":"10.77.0.9"}
	}`))
	if err != nil {
		t.Fatalf("parse inventory: %v", err)
	}
	if inventory.Hosts[0].AnsibleHost != "10.77.0.11" {
		t.Fatalf("ansible host = %q, want internal node address", inventory.Hosts[0].AnsibleHost)
	}
	if !inventory.Hosts[0].ProxyViaBastion {
		t.Fatal("remote internal node connection does not use the bastion")
	}
	rendered := string(renderInventoryYAML(inventory))
	if !strings.Contains(rendered, "ProxyCommand") || !strings.Contains(rendered, "root@198.51.100.9") {
		t.Fatalf("remote inventory lacks the expected bastion proxy command:\n%s", rendered)
	}
}

func TestInventoryRejectsInvalidMainIPWhenBastionExists(t *testing.T) {
	t.Parallel()

	_, err := parseTerraformInventory([]byte(`{
		"node_labels":{"value":["atum-node-1"]},
		"node_main_ips":{"value":["not-an-address"]},
		"node_internal_ips":{"value":["10.77.0.11"]},
		"load_balancer_ipv4":{"value":"10.77.0.10"},
		"dns_server":{"value":"10.77.0.1"},
		"bastion_main_ip":{"value":"10.77.0.9"},
		"bastion_internal_ip":{"value":"10.77.0.9"}
	}`))
	if err == nil || !strings.Contains(err.Error(), "node_main_ips[0]") {
		t.Fatalf("invalid main IP error = %v", err)
	}
}
