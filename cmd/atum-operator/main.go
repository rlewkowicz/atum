package main

import (
	"crypto/tls"
	"flag"
	"os"

	platformv1alpha1 "atum/operator/api/v1alpha1"
	"atum/operator/internal/controller"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	var healthAddress string
	flag.StringVar(&healthAddress, "health-probe-bind-address", ":8081", "Health probe address.")
	logOptions := zap.Options{Development: false}
	logOptions.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOptions)))

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(platformv1alpha1.AddToScheme(scheme))
	disableHTTP2 := func(config *tls.Config) { config.NextProtos = []string{"http/1.1"} }
	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{
			platformv1alpha1.SingletonNamespace: {},
		}},
		Metrics: metricsserver.Options{BindAddress: "0", TLSOpts: []func(*tls.Config){disableHTTP2}},
		HealthProbeBindAddress: healthAddress,
		LeaderElection: false,
	})
	if err != nil { ctrl.Log.Error(err, "create manager"); os.Exit(1) }
	if err := (&controller.PlatformConfigurationReconciler{
		Client: manager.GetClient(),
		SecretReader: manager.GetAPIReader(),
	}).SetupWithManager(manager); err != nil {
		ctrl.Log.Error(err, "create controller"); os.Exit(1)
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil { ctrl.Log.Error(err, "health check"); os.Exit(1) }
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil { ctrl.Log.Error(err, "ready check"); os.Exit(1) }
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil { ctrl.Log.Error(err, "run manager"); os.Exit(1) }
}
