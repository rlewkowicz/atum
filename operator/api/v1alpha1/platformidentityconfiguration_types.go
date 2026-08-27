package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	SingletonName      = "atum"
	SingletonNamespace = "atum-system"
	ConditionKeycloak  = "KeycloakReady"
	ConditionVault     = "VaultReady"
	ConditionReady     = "Ready"
)

// PlatformIdentityConfigurationSpec is the closed declaration of the Keycloak
// and Vault provider objects owned by Atum. Provider endpoints and Kubernetes
// credential names are fixed by the controller and are not extension points.
// +kubebuilder:validation:XValidation:rule="self.keycloak.clients.exists(c, c.id == self.vault.role.clientID && c.kind == 'Confidential')",message="vault.role.clientID must name one declared confidential client"
// +kubebuilder:validation:XValidation:rule="self.vault.role.scopes == self.keycloak.scopes",message="Vault role scopes must equal the canonical Keycloak scopes"
// +kubebuilder:validation:XValidation:rule="self.vault.externalGroup.policyName == self.vault.policy.name",message="Vault external group policyName must match the declared policy"
type PlatformIdentityConfigurationSpec struct {
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="domain is immutable after provider ownership is established"
	Domain   string         `json:"domain"`
	Keycloak KeycloakIntent `json:"keycloak"`
	Vault    VaultIntent    `json:"vault"`
}

type KeycloakIntent struct {
	// +kubebuilder:validation:Enum=master
	Realm         string        `json:"realm"`
	Administrator Administrator `json:"administrator"`
	GroupsScope   GroupsScope   `json:"groupsScope"`
	// +kubebuilder:validation:MinItems=4
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:UniqueItems=true
	// +kubebuilder:validation:items:Enum=openid;profile;email;groups
	// +kubebuilder:validation:XValidation:rule="self == ['openid', 'profile', 'email', 'groups']",message="scopes must be openid, profile, email, groups in canonical order"
	Scopes []string `json:"scopes"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=id
	Clients []KeycloakClient `json:"clients"`
}

type Administrator struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	Username string `json:"username"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	Group string `json:"group"`
	// +kubebuilder:validation:Enum=admin
	RealmRole string `json:"realmRole"`
}

type GroupsScope struct {
	// +kubebuilder:validation:Enum=atum-groups
	Name string `json:"name"`
	// +kubebuilder:validation:Enum=groups
	ClaimName string `json:"claimName"`
}

// +kubebuilder:validation:Enum=PublicPKCE;Confidential
type ClientKind string

const (
	ClientPublicPKCE   ClientKind = "PublicPKCE"
	ClientConfidential ClientKind = "Confidential"
)

type KeycloakClient struct {
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	ID   string     `json:"id"`
	Kind ClientKind `json:"kind"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:UniqueItems=true
	RedirectURIs []string `json:"redirectURIs"`
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:UniqueItems=true
	WebOrigins []string `json:"webOrigins,omitempty"`
	Audience   bool     `json:"audience,omitempty"`
}

type VaultIntent struct {
	// +kubebuilder:validation:Enum=oidc
	AuthPath      string             `json:"authPath"`
	Policy        VaultPolicy        `json:"policy"`
	Role          VaultRole          `json:"role"`
	ExternalGroup VaultExternalGroup `json:"externalGroup"`
}

type VaultPolicy struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	Name    string             `json:"name"`
	Purpose VaultPolicyPurpose `json:"purpose"`
}

// +kubebuilder:validation:Enum=PlatformAdministration
type VaultPolicyPurpose string

const (
	VaultPlatformAdministration         VaultPolicyPurpose = "PlatformAdministration"
	VaultPlatformAdministrationRoleName                    = "atum-admin"
)

type VaultRole struct {
	// +kubebuilder:validation:Enum=atum-admin
	Name string `json:"name"`
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	ClientID string `json:"clientID"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:UniqueItems=true
	RedirectURIs []string `json:"redirectURIs"`
	// +kubebuilder:validation:MinItems=4
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:UniqueItems=true
	// +kubebuilder:validation:items:Enum=openid;profile;email;groups
	Scopes []string `json:"scopes"`
	// +kubebuilder:validation:Enum=groups
	GroupsClaim string `json:"groupsClaim"`
}

type VaultExternalGroup struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	Claim string `json:"claim"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9-]{0,62}$`
	PolicyName string `json:"policyName"`
}

type PlatformIdentityConfigurationStatus struct {
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=6
	FailureCount int32 `json:"failureCount,omitempty"`
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.type in ['KeycloakReady', 'VaultReady', 'Ready'])",message="conditions are limited to KeycloakReady, VaultReady, and Ready"
	// +kubebuilder:validation:XValidation:rule="self.all(c, size(c.message) <= 512)",message="condition messages must not exceed 512 characters"
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=atumidentity
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'atum'",message="PlatformIdentityConfiguration must use the singleton name atum"
type PlatformIdentityConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PlatformIdentityConfigurationSpec   `json:"spec"`
	Status            PlatformIdentityConfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type PlatformIdentityConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlatformIdentityConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PlatformIdentityConfiguration{}, &PlatformIdentityConfigurationList{})
}
