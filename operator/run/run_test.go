package run

import (
	"testing"

	platformv1alpha1 "atum/operator/api/v1alpha1"
)

func TestManagerCacheIsFixedToIdentityNamespace(t *testing.T) {
	t.Parallel()

	namespaces := managerCacheOptions().DefaultNamespaces
	if len(namespaces) != 1 {
		t.Fatalf("cache namespaces = %v", namespaces)
	}
	if _, exists := namespaces[platformv1alpha1.SingletonNamespace]; !exists {
		t.Fatalf("cache does not contain %q", platformv1alpha1.SingletonNamespace)
	}
}
