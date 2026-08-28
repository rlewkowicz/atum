package controller

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	platformv1alpha1 "atum/operator/api/v1alpha1"
	"atum/operator/internal/provider"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	finalizerName          = "platform.atum.dev/provider-cleanup"
	credentialSecretName   = "atum-provider-credentials"
	caSecretName           = "atum-provider-ca"
	vaultTokenNamespace    = "vault"
	vaultTokenSecretName   = "vault-token"
	vaultTokenKey          = "key"
	providerCAKey          = "ca.crt"
	successInterval        = 10 * time.Minute
	initialFailureInterval = 5 * time.Second
	maxFailureInterval     = 5 * time.Minute
	maxConditionMessage    = 512
)

type PlatformIdentityConfigurationReconciler struct {
	client.Client
	SecretReader client.Reader
}

// +kubebuilder:rbac:groups=platform.atum.dev,resources=platformidentityconfigurations,verbs=get;list;watch,namespace=atum-system
// +kubebuilder:rbac:groups=platform.atum.dev,resources=platformidentityconfigurations,resourceNames=atum,verbs=patch,namespace=atum-system
// +kubebuilder:rbac:groups=platform.atum.dev,resources=platformidentityconfigurations/status,resourceNames=atum,verbs=get;update;patch,namespace=atum-system
// +kubebuilder:rbac:groups=platform.atum.dev,resources=platformidentityconfigurations/finalizers,resourceNames=atum,verbs=update,namespace=atum-system
// +kubebuilder:rbac:groups="",resources=secrets,resourceNames=atum-provider-credentials;atum-provider-ca,verbs=get,namespace=atum-system

func (r *PlatformIdentityConfigurationReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	if request.Namespace != platformv1alpha1.SingletonNamespace || request.Name != platformv1alpha1.SingletonName {
		return ctrl.Result{}, nil
	}
	var object platformv1alpha1.PlatformIdentityConfiguration
	if err := r.Get(ctx, request.NamespacedName, &object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !object.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &object)
	}
	if err := validateRuntime(&object.Spec); err != nil {
		return r.record(ctx, &object,
			providerState{reason: "InvalidIntent", message: err.Error(), terminal: true},
			providerState{reason: "InvalidIntent", message: err.Error(), terminal: true},
		)
	}
	if !controllerutil.ContainsFinalizer(&object, finalizerName) {
		base := object.DeepCopy()
		controllerutil.AddFinalizer(&object, finalizerName)
		if err := r.Patch(ctx, &object, client.MergeFrom(base)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	ca, err := r.secretKey(ctx, platformv1alpha1.SingletonNamespace, caSecretName, providerCAKey)
	if err != nil {
		state := failureState("ProviderTrustUnavailable", err)
		return r.record(ctx, &object, state, providerState{
			reason: "DependencyNotReady", message: "Keycloak provider reconciliation must complete first",
		})
	}
	credentials, err := r.keycloakCredentials(ctx)
	if err != nil {
		state := failureState("CredentialsUnavailable", err)
		return r.record(ctx, &object, state, providerState{
			reason: "DependencyNotReady", message: "Keycloak provider reconciliation must complete first",
		})
	}
	keycloakErr := r.reconcileKeycloak(ctx, &object, credentials, ca)
	keycloakState := stateFor("KeycloakReconciled", keycloakErr)
	if keycloakErr != nil {
		return r.record(ctx, &object, keycloakState, providerState{
			reason: "DependencyNotReady", message: "Keycloak provider reconciliation must complete first",
		})
	}
	vaultToken, err := r.secretKey(ctx, vaultTokenNamespace, vaultTokenSecretName, vaultTokenKey)
	if err != nil {
		return r.record(ctx, &object, keycloakState, failureState("VaultCredentialsUnavailable", err))
	}
	vaultErr := r.reconcileVault(ctx, &object, credentials, ca, vaultToken)
	return r.record(ctx, &object, keycloakState, stateFor("VaultReconciled", vaultErr))
}

type providerState struct {
	ready    bool
	reason   string
	message  string
	terminal bool
}

func stateFor(success string, err error) providerState {
	if err == nil {
		return providerState{ready: true, reason: success, message: "Declared provider state is current"}
	}
	reason := "ProviderError"
	if provider.IsTerminal(err) {
		reason = "ProviderConflict"
	}
	return providerState{reason: reason, message: err.Error(), terminal: provider.IsTerminal(err)}
}

func failureState(reason string, err error) providerState {
	return providerState{reason: reason, message: err.Error()}
}

func (r *PlatformIdentityConfigurationReconciler) secret(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	key := types.NamespacedName{Namespace: namespace, Name: name}
	switch key {
	case types.NamespacedName{Namespace: platformv1alpha1.SingletonNamespace, Name: credentialSecretName},
		types.NamespacedName{Namespace: platformv1alpha1.SingletonNamespace, Name: caSecretName},
		types.NamespacedName{Namespace: vaultTokenNamespace, Name: vaultTokenSecretName}:
	default:
		return nil, fmt.Errorf("Secret read %s/%s is outside the fixed provider credential contract", namespace, name)
	}
	var object corev1.Secret
	if err := r.SecretReader.Get(ctx, key, &object); err != nil {
		return nil, fmt.Errorf("read %s/%s: %w", namespace, name, err)
	}
	return object.Data, nil
}

func (r *PlatformIdentityConfigurationReconciler) secretKey(ctx context.Context, namespace, name, key string) ([]byte, error) {
	data, err := r.secret(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	if len(data[key]) == 0 {
		return nil, fmt.Errorf("%s/%s key %q is empty", namespace, name, key)
	}
	return data[key], nil
}

func (r *PlatformIdentityConfigurationReconciler) keycloakCredentials(ctx context.Context) (map[string][]byte, error) {
	data, err := r.secret(ctx, platformv1alpha1.SingletonNamespace, credentialSecretName)
	if err != nil {
		return nil, err
	}
	for _, key := range [...]string{
		"ATUM_IDENTITY_ADMIN_USERNAME",
		"ATUM_IDENTITY_ADMIN_PASSWORD",
		"ATUM_IDENTITY_BOOTSTRAP_PASSWORD",
	} {
		if len(data[key]) == 0 {
			return nil, fmt.Errorf("%s/%s key %q is empty", platformv1alpha1.SingletonNamespace, credentialSecretName, key)
		}
	}
	return data, nil
}

func (r *PlatformIdentityConfigurationReconciler) keycloak(ctx context.Context, object *platformv1alpha1.PlatformIdentityConfiguration, credentials map[string][]byte, ca []byte) (*provider.Keycloak, error) {
	baseURL := "https://keycloak." + object.Spec.Domain + "/auth"
	keycloak, adminErr := provider.NewKeycloak(ctx, baseURL, ca, object.Spec.Keycloak.Realm,
		string(credentials["ATUM_IDENTITY_ADMIN_USERNAME"]),
		string(credentials["ATUM_IDENTITY_ADMIN_PASSWORD"]),
	)
	if adminErr == nil {
		return keycloak, nil
	}
	keycloak, bootstrapErr := provider.NewKeycloak(ctx, baseURL, ca, object.Spec.Keycloak.Realm,
		"atum-bootstrap", string(credentials["ATUM_IDENTITY_BOOTSTRAP_PASSWORD"]))
	if bootstrapErr != nil {
		return nil, fmt.Errorf("authenticate Keycloak administrator or bootstrap account: %w", errors.Join(adminErr, bootstrapErr))
	}
	return keycloak, nil
}

func (r *PlatformIdentityConfigurationReconciler) reconcileKeycloak(ctx context.Context, object *platformv1alpha1.PlatformIdentityConfiguration, credentials map[string][]byte, ca []byte) error {
	keycloak, err := r.keycloak(ctx, object, credentials, ca)
	if err != nil {
		return err
	}
	defer keycloak.Close()
	return keycloak.Reconcile(ctx, object.Spec.Domain, object.Spec.Keycloak, credentials)
}

func (r *PlatformIdentityConfigurationReconciler) reconcileVault(ctx context.Context, object *platformv1alpha1.PlatformIdentityConfiguration, credentials map[string][]byte, ca, token []byte) error {
	vault, err := provider.NewVault("https://vault."+object.Spec.Domain, ca, string(token))
	if err != nil {
		return err
	}
	defer vault.Close()
	return vault.Reconcile(ctx,
		"https://keycloak."+object.Spec.Domain+"/auth/realms/"+object.Spec.Keycloak.Realm,
		ca, object.Spec.Vault, credentials,
	)
}

func (r *PlatformIdentityConfigurationReconciler) record(ctx context.Context, object *platformv1alpha1.PlatformIdentityConfiguration, keycloak, vault providerState) (ctrl.Result, error) {
	return r.recordAttempt(ctx, object, keycloak, vault, false)
}

func (r *PlatformIdentityConfigurationReconciler) recordCleanup(ctx context.Context, object *platformv1alpha1.PlatformIdentityConfiguration, keycloak, vault providerState) (ctrl.Result, error) {
	return r.recordAttempt(ctx, object, keycloak, vault, true)
}

func (r *PlatformIdentityConfigurationReconciler) recordAttempt(ctx context.Context, object *platformv1alpha1.PlatformIdentityConfiguration, keycloak, vault providerState, retryTerminal bool) (ctrl.Result, error) {
	base := object.DeepCopy()
	if object.Status.ObservedGeneration != object.Generation {
		object.Status.FailureCount = 0
	}
	object.Status.ObservedGeneration = object.Generation
	setCondition(&object.Status.Conditions, object.Generation, platformv1alpha1.ConditionKeycloak, keycloak)
	setCondition(&object.Status.Conditions, object.Generation, platformv1alpha1.ConditionVault, vault)
	ready := keycloak.ready && vault.ready
	readyState := providerState{
		ready:    ready,
		reason:   "ProvidersReady",
		message:  "Keycloak and Vault provider state is current",
		terminal: keycloak.terminal || vault.terminal,
	}
	if !ready {
		readyState.reason = "ProvidersNotReady"
		readyState.message = "One or more provider states are not current"
	}
	setCondition(&object.Status.Conditions, object.Generation, platformv1alpha1.ConditionReady, readyState)
	if ready {
		object.Status.FailureCount = 0
	} else if object.Status.FailureCount < 6 {
		object.Status.FailureCount++
	}
	if err := r.Status().Patch(ctx, object, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, fmt.Errorf("record PlatformIdentityConfiguration status: %w", err)
	}
	if ready {
		return ctrl.Result{RequeueAfter: successInterval}, nil
	}
	if readyState.terminal && !retryTerminal {
		return ctrl.Result{}, nil
	}
	delay := initialFailureInterval << object.Status.FailureCount
	if delay > maxFailureInterval {
		delay = maxFailureInterval
	}
	return ctrl.Result{RequeueAfter: delay}, nil
}

func setCondition(conditions *[]metav1.Condition, generation int64, conditionType string, state providerState) {
	status := metav1.ConditionFalse
	if state.ready {
		status = metav1.ConditionTrue
	}
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             state.reason,
		Message:            boundedMessage(state.message),
		ObservedGeneration: generation,
	})
}

func boundedMessage(message string) string {
	message = strings.Map(func(value rune) rune {
		if value < ' ' || value == '\u007f' {
			return ' '
		}
		return value
	}, message)
	if len(message) <= maxConditionMessage {
		return message
	}
	return message[:maxConditionMessage]
}

func (r *PlatformIdentityConfigurationReconciler) finalize(ctx context.Context, object *platformv1alpha1.PlatformIdentityConfiguration) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(object, finalizerName) {
		return ctrl.Result{}, nil
	}
	ca, caErr := r.secretKey(ctx, platformv1alpha1.SingletonNamespace, caSecretName, providerCAKey)
	var keycloakErr, vaultErr error
	credentials, credentialsErr := r.keycloakCredentials(ctx)
	if caErr == nil && credentialsErr == nil {
		keycloak, err := r.keycloak(ctx, object, credentials, ca)
		if err != nil {
			keycloakErr = err
		} else {
			keycloakErr = keycloak.Cleanup(ctx)
			keycloak.Close()
		}
	} else if !credentialSourceGone(caErr) && !credentialSourceGone(credentialsErr) {
		keycloakErr = errors.Join(caErr, credentialsErr)
	}
	token, tokenErr := r.secretKey(ctx, vaultTokenNamespace, vaultTokenSecretName, vaultTokenKey)
	if caErr == nil && tokenErr == nil {
		vault, err := provider.NewVault("https://vault."+object.Spec.Domain, ca, string(token))
		if err != nil {
			vaultErr = err
		} else {
			vaultErr = vault.Cleanup(ctx)
			vault.Close()
		}
	} else if !credentialSourceGone(caErr) && !credentialSourceGone(tokenErr) {
		vaultErr = errors.Join(caErr, tokenErr)
	}
	cleanupErr := errors.Join(keycloakErr, vaultErr)
	if cleanupErr != nil {
		return r.recordCleanup(ctx, object, stateFor("KeycloakCleanup", keycloakErr), stateFor("VaultCleanup", vaultErr))
	}
	base := object.DeepCopy()
	controllerutil.RemoveFinalizer(object, finalizerName)
	if err := r.Patch(ctx, object, client.MergeFrom(base)); err != nil &&
		!apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("remove PlatformIdentityConfiguration finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func credentialSourceGone(err error) bool {
	return err != nil && (apierrors.IsNotFound(err) || strings.Contains(err.Error(), " is empty"))
}

func validateRuntime(spec *platformv1alpha1.PlatformIdentityConfigurationSpec) error {
	for _, item := range spec.Keycloak.Clients {
		if err := validatePlatformURIs(spec.Domain, "client "+item.ID, item.RedirectURIs); err != nil {
			return err
		}
		if err := validatePlatformURIs(spec.Domain, "client "+item.ID, item.WebOrigins); err != nil {
			return err
		}
	}
	if err := validatePlatformURIs(spec.Domain, "Vault role "+spec.Vault.Role.Name, spec.Vault.Role.RedirectURIs); err != nil {
		return err
	}
	return nil
}

func validatePlatformURIs(domain, owner string, values []string) error {
	for _, value := range values {
		parsed, err := url.Parse(value)
		host := parsed.Hostname()
		if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
			parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
			len(host) <= len(domain)+1 || !strings.HasSuffix(host, "."+domain) {
			return fmt.Errorf("%s URI %q is outside the platform domain", owner, value)
		}
	}
	return nil
}

func (r *PlatformIdentityConfigurationReconciler) SetupWithManager(manager ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(manager).
		For(&platformv1alpha1.PlatformIdentityConfiguration{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Named("platformidentityconfiguration").
		Complete(r)
}
