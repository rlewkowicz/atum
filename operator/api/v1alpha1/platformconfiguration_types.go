package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	SingletonName      = "atum"
	SingletonNamespace = "atum-system"
	ConditionKeycloak  = "KeycloakReady"
	ConditionVault     = "VaultReady"
	ConditionReady     = "Ready"
)

// PlatformConfigurationSpec is a closed, typed declaration of the provider
// objects Atum owns. Provider endpoints and Kubernetes credential names are
// deliberately fixed by the controller and are not extension points.
type PlatformConfigurationSpec struct {
	Domain   string         `json:"domain"`
	Keycloak KeycloakIntent `json:"keycloak"`
	Vault    VaultIntent    `json:"vault"`
}

type KeycloakIntent struct {
	Realm         string          `json:"realm"`
	Administrator Administrator   `json:"administrator"`
	GroupsScope   GroupsScope     `json:"groupsScope"`
	Scopes        []string        `json:"scopes"`
	Clients       []KeycloakClient `json:"clients"`
}

type Administrator struct {
	Username  string `json:"username"`
	Group     string `json:"group"`
	RealmRole string `json:"realmRole"`
}

type GroupsScope struct {
	Name      string `json:"name"`
	ClaimName string `json:"claimName"`
}

type ClientKind string

const (
	ClientPublicPKCE   ClientKind = "PublicPKCE"
	ClientConfidential ClientKind = "Confidential"
)

type KeycloakClient struct {
	ID            string     `json:"id"`
	Kind          ClientKind `json:"kind"`
	RedirectURIs  []string   `json:"redirectURIs"`
	WebOrigins    []string   `json:"webOrigins,omitempty"`
	Audience      bool       `json:"audience,omitempty"`
}

type VaultIntent struct {
	AuthPath      string              `json:"authPath"`
	Policy        VaultPolicy         `json:"policy"`
	Role          VaultRole           `json:"role"`
	ExternalGroup VaultExternalGroup  `json:"externalGroup"`
}

type VaultPolicy struct {
	Name    string             `json:"name"`
	Purpose VaultPolicyPurpose `json:"purpose"`
}

type VaultPolicyPurpose string

const VaultPlatformAdministration VaultPolicyPurpose = "PlatformAdministration"

type VaultRole struct {
	Name         string   `json:"name"`
	ClientID     string   `json:"clientID"`
	RedirectURIs []string `json:"redirectURIs"`
	Scopes       []string `json:"scopes"`
	GroupsClaim  string   `json:"groupsClaim"`
}

type VaultExternalGroup struct {
	Name       string `json:"name"`
	Claim      string `json:"claim"`
	PolicyName string `json:"policyName"`
}

type PlatformConfigurationStatus struct {
	ObservedGeneration int64               `json:"observedGeneration,omitempty"`
	FailureCount       int32               `json:"failureCount,omitempty"`
	Conditions         []metav1.Condition  `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=atumconfig
type PlatformConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PlatformConfigurationSpec   `json:"spec,omitempty"`
	Status            PlatformConfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type PlatformConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlatformConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PlatformConfiguration{}, &PlatformConfigurationList{})
}
