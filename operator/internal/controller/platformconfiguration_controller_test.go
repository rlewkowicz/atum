package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	platformv1alpha1 "atum/operator/api/v1alpha1"
	"atum/operator/internal/provider"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidatePlatformConfiguration(t *testing.T) {
	spec := validSpec()
	if err := validate(&spec); err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	spec.Keycloak.Clients = append(spec.Keycloak.Clients, spec.Keycloak.Clients[0])
	if err := validate(&spec); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate client error = %v", err)
	}
}

func TestConditionsUseCurrentGenerationAndBoundDiagnostics(t *testing.T) {
	var conditions []metav1.Condition
	setCondition(&conditions, 19, platformv1alpha1.ConditionKeycloak, providerState{
		reason: "ProviderError",
		message: strings.Repeat("sensitive\n", 100),
	})
	if len(conditions) != 1 || conditions[0].ObservedGeneration != 19 {
		t.Fatalf("conditions = %#v", conditions)
	}
	if len(conditions[0].Message) > maxConditionMessage || strings.Contains(conditions[0].Message, "\n") {
		t.Fatalf("condition message was not bounded and sanitized: %q", conditions[0].Message)
	}
	state := stateFor("unused", provider.Conflict("unowned collision"))
	if !state.terminal || state.reason != "ProviderConflict" {
		t.Fatalf("conflict state = %#v", state)
	}
}

func TestTerminalCleanupCollisionRequeuesForExternalRepair(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := platformv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Now())
	object := &platformv1alpha1.PlatformConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: platformv1alpha1.SingletonName,
			Namespace: platformv1alpha1.SingletonNamespace,
			Generation: 11,
			Finalizers: []string{finalizerName},
			DeletionTimestamp: &now,
		},
	}
	kubernetes := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(object).
		WithObjects(object).
		Build()
	reconciler := &PlatformConfigurationReconciler{
		Client: kubernetes, SecretReader: kubernetes,
	}
	result, err := reconciler.recordCleanup(
		context.Background(),
		object,
		stateFor("unused", provider.Conflict("unowned provider collision")),
		providerState{ready: true, reason: "VaultCleanup", message: "Scoped cleanup is current"},
	)
	if err != nil {
		t.Fatalf("record cleanup collision: %v", err)
	}
	if result.RequeueAfter < initialFailureInterval || result.RequeueAfter > maxFailureInterval {
		t.Fatalf("cleanup requeue = %s", result.RequeueAfter)
	}
	var current platformv1alpha1.PlatformConfiguration
	if err := kubernetes.Get(context.Background(), types.NamespacedName{
		Name: platformv1alpha1.SingletonName,
		Namespace: platformv1alpha1.SingletonNamespace,
	}, &current); err != nil {
		t.Fatalf("read deleting singleton: %v", err)
	}
	if len(current.Finalizers) != 1 || current.Finalizers[0] != finalizerName {
		t.Fatalf("terminal collision released finalizer: %v", current.Finalizers)
	}
	if current.Status.ObservedGeneration != 11 {
		t.Fatalf("observed generation = %d", current.Status.ObservedGeneration)
	}
}

func TestSecretReadsUseOnlyTheDirectReader(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cached := fake.NewClientBuilder().WithScheme(scheme).Build()
	direct := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: caSecretName,
			Namespace: platformv1alpha1.SingletonNamespace,
		},
		Data: map[string][]byte{providerCAKey: []byte("provider-ca")},
	}).Build()
	reconciler := &PlatformConfigurationReconciler{
		Client: cached, SecretReader: direct,
	}
	value, err := reconciler.secretKey(
		context.Background(),
		platformv1alpha1.SingletonNamespace,
		caSecretName,
		providerCAKey,
	)
	if err != nil {
		t.Fatalf("read fixed Secret through direct reader: %v", err)
	}
	if string(value) != "provider-ca" {
		t.Fatalf("Secret value = %q", value)
	}
	var absent corev1.Secret
	if err := cached.Get(context.Background(), types.NamespacedName{
		Name: caSecretName,
		Namespace: platformv1alpha1.SingletonNamespace,
	}, &absent); !apierrors.IsNotFound(err) {
		t.Fatalf("cached client unexpectedly supplied Secret: %v", err)
	}
	if _, err := reconciler.secret(
		context.Background(), "other", "arbitrary",
	); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("arbitrary Secret read error = %v", err)
	}
}

func TestDeletingInvalidConfigurationDoesNotWaitForPrunedSecrets(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := platformv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := metav1.NewTime(time.Now())
	object := &platformv1alpha1.PlatformConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: platformv1alpha1.SingletonName,
			Namespace: platformv1alpha1.SingletonNamespace,
			Finalizers: []string{finalizerName},
			DeletionTimestamp: &now,
		},
	}
	kubernetes := fake.NewClientBuilder().WithScheme(scheme).WithObjects(object).Build()
	reconciler := &PlatformConfigurationReconciler{
		Client: kubernetes, SecretReader: kubernetes,
	}
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: platformv1alpha1.SingletonName,
			Namespace: platformv1alpha1.SingletonNamespace,
		},
	})
	if err != nil {
		t.Fatalf("reconcile deletion: %v", err)
	}
	var current platformv1alpha1.PlatformConfiguration
	err = kubernetes.Get(context.Background(), types.NamespacedName{
		Name: platformv1alpha1.SingletonName,
		Namespace: platformv1alpha1.SingletonNamespace,
	}, &current)
	if err == nil && len(current.Finalizers) != 0 {
		t.Fatalf("finalizers = %v", current.Finalizers)
	}
}

func TestValidateRejectsProviderExtensionPoints(t *testing.T) {
	spec := validSpec()
	spec.Keycloak.Clients[0].RedirectURIs[0] = "https://outside.example/callback"
	if err := validate(&spec); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside callback error = %v", err)
	}
	spec = validSpec()
	spec.Vault.Policy.Purpose = "Arbitrary"
	if err := validate(&spec); err == nil || !strings.Contains(err.Error(), "supported OIDC contract") {
		t.Fatalf("arbitrary policy purpose error = %v", err)
	}
}

func validSpec() platformv1alpha1.PlatformConfigurationSpec {
	return platformv1alpha1.PlatformConfigurationSpec{
		Domain: "atum.test",
		Keycloak: platformv1alpha1.KeycloakIntent{
			Realm: "master",
			Administrator: platformv1alpha1.Administrator{
				Username: "atum", Group: "atum-admins", RealmRole: "admin",
			},
			GroupsScope: platformv1alpha1.GroupsScope{Name: "atum-groups", ClaimName: "groups"},
			Scopes: []string{"openid", "profile", "email", "groups"},
			Clients: []platformv1alpha1.KeycloakClient{{
				ID: "atum-vault", Kind: platformv1alpha1.ClientConfidential,
				RedirectURIs: []string{"https://vault.atum.test/callback"},
			}},
		},
		Vault: platformv1alpha1.VaultIntent{
			AuthPath: "oidc",
			Policy: platformv1alpha1.VaultPolicy{
				Name: "atum-admin", Purpose: platformv1alpha1.VaultPlatformAdministration,
			},
			Role: platformv1alpha1.VaultRole{
				Name: "atum-admin", ClientID: "atum-vault",
				RedirectURIs: []string{"https://vault.atum.test/callback"},
				Scopes: []string{"openid", "profile", "email", "groups"},
				GroupsClaim: "groups",
			},
			ExternalGroup: platformv1alpha1.VaultExternalGroup{
				Name: "atum-admins", Claim: "atum-admins", PolicyName: "atum-admin",
			},
		},
	}
}
