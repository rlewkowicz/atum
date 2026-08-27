// Package v1alpha1 defines Atum's sole identity-provider configuration API.
// +kubebuilder:object:generate=true
// +groupName=platform.atum.dev
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "platform.atum.dev", Version: "v1alpha1"}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)
