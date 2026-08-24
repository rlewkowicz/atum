variable "ATUM_CACHE_REGISTRY" {
  default = "10.77.0.9:32443/buildkit"
}

variable "ATUM_BOOTSTRAP_OUTPUT" {
  default = "type=registry,oci-mediatypes=true,rewrite-timestamp=true"
}

variable "ATUM_DEBIAN_IMAGE" {
  default = "docker.io/library/debian@sha256:32ccbb2ff8fdcb839bbe9c03c33e4e962b51fe8859249f821638d674b0b88d66"
}

variable "ATUM_PLATFORM" {
  default = "linux/amd64"
}

variable "ATUM_SBOM_GENERATOR_IMAGE" {
  default = "10.77.0.9:32443/atum/sbom-scanner:1.11.0"
}

variable "SOURCE_DATE_EPOCH" {
  default = "0"
}

group "default" {
  targets = ["postgresql-17-compat", "postgresql-18-compat", "redis-compat", "bigbang-harbor-redis-compat", "redis-exporter-compat", "grafana-plugins", "openbao"]
}

group "source-build-all" {
  targets = [
    "debian-runtime",
    "go-toolchain",
    "node-toolchain-20",
    "node-toolchain-22",
    "node-toolchain-24",
    "python-toolchain",
    "ruby-toolchain",
    "buildkit",
    "sbom-scanner",
    "build-job",
    "busybox",
    "kubectl-shell",
    "flux-source-controller",
    "flux-kustomize-controller",
    "flux-helm-controller",
    "flux-notification-controller",
    "cert-manager-controller",
    "cert-manager-webhook",
    "cert-manager-cainjector",
    "cert-manager-startupapicheck",
    "cert-manager-acmesolver",
    "harbor-nginx",
    "harbor-portal",
    "harbor-core",
    "harbor-jobservice",
    "harbor-registry",
    "harbor-registryctl",
    "authservice",
    "istio-pilot",
    "istio-proxy",
    "kiali-operator",
    "kiali-server",
    "kyverno-admission-controller",
    "kyverno-preflight",
    "kyverno-cli",
    "kyverno-background-controller",
    "kyverno-cleanup-controller",
    "kyverno-reports-controller",
    "kyverno-readiness-checker",
    "policy-reporter",
    "policy-reporter-ui",
    "policy-reporter-kyverno-plugin",
    "kube-webhook-certgen",
    "fluent-bit",
    "configmap-reload",
    "tempo",
    "prometheus",
    "alertmanager",
    "prometheus-operator",
    "prometheus-config-reloader",
    "thanos",
    "kube-state-metrics",
    "node-exporter",
    "grafana",
    "k8s-sidecar",
    "keycloak",
    "postgresql-17",
    "postgresql-18",
    "redis-8-4",
    "bigbang-harbor-redis",
    "redis-exporter",
    "minio",
    "minio-client",
    "openbao",
    "vault-k8s",
    "opensearch",
    "opensearch-dashboards",
    "opensearch-operator",
    "velero",
    "velero-aws",
    "gitlab-certificates",
    "gitlab-base",
    "gitlab-container-registry",
    "gitlab-toolbox",
    "gitlab-webservice",
    "gitlab-workhorse",
    "gitlab-sidekiq",
    "gitlab-shell",
    "gitaly",
    "gitlab-exporter",
    "gitlab-kas",
    "cfssl-self-sign",
  ]
}

group "foundation" {
  targets = [
    "debian-runtime",
    "go-toolchain",
    "node-toolchain-20",
    "node-toolchain-22",
    "node-toolchain-24",
    "python-toolchain",
    "ruby-toolchain",
    "busybox",
    "kubectl-shell",
  ]
}

group "builders" {
  targets = [
    "go-toolchain",
    "node-toolchain-20",
    "node-toolchain-22",
    "node-toolchain-24",
    "python-toolchain",
    "ruby-toolchain",
    "buildkit",
    "sbom-scanner",
    "build-job",
    "gitlab-base",
  ]
}

group "prep" {
  targets = [
    "busybox",
    "flux-source-controller",
    "flux-kustomize-controller",
    "flux-helm-controller",
    "flux-notification-controller",
    "cert-manager-controller",
    "cert-manager-webhook",
    "cert-manager-cainjector",
    "cert-manager-startupapicheck",
    "cert-manager-acmesolver",
  ]
}

group "bigbang" {
  targets = [
    "debian-runtime",
    "busybox",
    "kubectl-shell",
    "harbor-nginx",
    "harbor-portal",
    "harbor-core",
    "harbor-jobservice",
    "harbor-registry",
    "harbor-registryctl",
    "authservice",
    "istio-pilot",
    "istio-proxy",
    "kiali-operator",
    "kiali-server",
    "kyverno-admission-controller",
    "kyverno-preflight",
    "kyverno-cli",
    "kyverno-background-controller",
    "kyverno-cleanup-controller",
    "kyverno-reports-controller",
    "kyverno-readiness-checker",
    "policy-reporter",
    "policy-reporter-ui",
    "policy-reporter-kyverno-plugin",
    "kube-webhook-certgen",
    "fluent-bit",
    "configmap-reload",
    "tempo",
    "prometheus",
    "alertmanager",
    "prometheus-operator",
    "prometheus-config-reloader",
    "thanos",
    "kube-state-metrics",
    "node-exporter",
    "grafana",
    "k8s-sidecar",
    "keycloak",
    "postgresql-17",
    "postgresql-18",
    "redis-8-4",
    "bigbang-harbor-redis",
    "redis-exporter",
    "minio",
    "minio-client",
    "openbao",
    "vault-k8s",
    "opensearch",
    "opensearch-dashboards",
    "opensearch-operator",
    "velero",
    "velero-aws",
    "gitlab-certificates",
    "gitlab-base",
    "gitlab-container-registry",
    "gitlab-toolbox",
    "gitlab-webservice",
    "gitlab-workhorse",
    "gitlab-sidekiq",
    "gitlab-shell",
    "gitaly",
    "gitlab-exporter",
    "gitlab-kas",
    "cfssl-self-sign",
  ]
}

# Run this group once against an empty registry. Its provenance-only scanner
# and build-job outputs make the normal SBOM-attested graph and Forgejo
# workflow self-hosting; the normal groups then replace both tags.
group "bootstrap-builders" {
  targets = ["buildkit-bootstrap-publish", "sbom-scanner-bootstrap", "build-job-bootstrap"]
}

target "_common" {
  context   = "."
  platforms = [ATUM_PLATFORM]
  args = {
    ATUM_DEBIAN_IMAGE             = ATUM_DEBIAN_IMAGE
    ATUM_IMAGE_CREATED            = "1970-01-01T00:00:00Z"
    BUILDKIT_CONTEXT_KEEP_GIT_DIR = "1"
    SOURCE_DATE_EPOCH             = SOURCE_DATE_EPOCH
  }
  output = ["type=image,oci-mediatypes=true,rewrite-timestamp=true"]
}

target "_attested" {
  inherits = ["_common"]
  attest = [
    "type=provenance,mode=max",
    "type=sbom,generator=${ATUM_SBOM_GENERATOR_IMAGE}",
  ]
}

target "_provenance_only" {
  inherits = ["_common"]
  attest   = ["type=provenance,mode=max"]
}

target "debian-runtime" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "debian-runtime"
  tags       = ["10.77.0.9:32443/atum/debian-runtime:13-slim-r1"]
  args = {
    ATUM_IMAGE_LICENSES = "GPL-2.0-or-later"
    ATUM_IMAGE_REVISION = "sha256:32ccbb2ff8fdcb839bbe9c03c33e4e962b51fe8859249f821638d674b0b88d66"
    ATUM_IMAGE_SOURCE   = "https://github.com/debuerreotype/docker-debian-artifacts"
    ATUM_IMAGE_TITLE    = "debian-runtime"
    ATUM_IMAGE_VERSION  = "13-slim"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/debian-runtime:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/debian-runtime:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

# These cache-only producers break the scanner bootstrap cycle. They provide
# named build contexts without attempting to emit an SBOM before the Atum
# scanner exists.
target "debian-runtime-bootstrap" {
  inherits   = ["_common"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "debian-runtime"
  output     = ["type=cacheonly"]
  cache-from = []
  cache-to   = []
  args = {
    ATUM_IMAGE_LICENSES = "GPL-2.0-or-later"
    ATUM_IMAGE_REVISION = "sha256:32ccbb2ff8fdcb839bbe9c03c33e4e962b51fe8859249f821638d674b0b88d66"
    ATUM_IMAGE_SOURCE   = "https://github.com/debuerreotype/docker-debian-artifacts"
    ATUM_IMAGE_TITLE    = "debian-runtime"
    ATUM_IMAGE_VERSION  = "13-slim"
  }
}

target "go-toolchain" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "go-toolchain"
  tags       = ["10.77.0.9:32443/atum/go-toolchain:1.26.3-debian13-r1"]
  contexts = {
    go_bootstrap_source = "https://go.googlesource.com/go.git?tag=go1.24.6&checksum=7f36edc26d4e3becb6d9c9008ff00f260bb19055"
    go_source           = "https://go.googlesource.com/go.git?tag=go1.26.3&checksum=2dc996f71b0ebafb77e64433e58333e049488a3c"
  }
  args = {
    ATUM_IMAGE_LICENSES = "BSD-3-Clause"
    ATUM_IMAGE_REVISION = "7f36edc26d4e3becb6d9c9008ff00f260bb19055+2dc996f71b0ebafb77e64433e58333e049488a3c"
    ATUM_IMAGE_SOURCE   = "https://go.googlesource.com/go"
    ATUM_IMAGE_TITLE    = "go-toolchain"
    ATUM_IMAGE_VERSION  = "1.26.3"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/go-toolchain:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/go-toolchain:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "go-toolchain-bootstrap" {
  inherits   = ["_common"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "go-toolchain"
  output     = ["type=cacheonly"]
  cache-from = []
  cache-to   = []
  contexts = {
    go_bootstrap_source = "https://go.googlesource.com/go.git?tag=go1.24.6&checksum=7f36edc26d4e3becb6d9c9008ff00f260bb19055"
    go_source           = "https://go.googlesource.com/go.git?tag=go1.26.3&checksum=2dc996f71b0ebafb77e64433e58333e049488a3c"
  }
  args = {
    ATUM_IMAGE_LICENSES = "BSD-3-Clause"
    ATUM_IMAGE_REVISION = "7f36edc26d4e3becb6d9c9008ff00f260bb19055+2dc996f71b0ebafb77e64433e58333e049488a3c"
    ATUM_IMAGE_SOURCE   = "https://go.googlesource.com/go"
    ATUM_IMAGE_TITLE    = "go-toolchain"
    ATUM_IMAGE_VERSION  = "1.26.3"
  }
}

target "node-toolchain-20" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "node-toolchain-20"
  tags       = ["10.77.0.9:32443/atum/node-toolchain:20.20.2-debian13-r1"]
  contexts = {
    node_20_source = "https://github.com/nodejs/node.git?tag=v20.20.2&checksum=35e07843146797923006aa01c6daabf4f53a4fb9"
  }
  args = {
    ATUM_IMAGE_LICENSES = "MIT"
    ATUM_IMAGE_REVISION = "3626fea570e44896ad99aaf3bf6e59def5adede5"
    ATUM_IMAGE_SOURCE   = "https://github.com/nodejs/node"
    ATUM_IMAGE_TITLE    = "node-toolchain-20"
    ATUM_IMAGE_VERSION  = "20.20.2"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/node-toolchain-20:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/node-toolchain-20:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "node-toolchain-22" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "node-toolchain-22"
  tags       = ["10.77.0.9:32443/atum/node-toolchain:22.23.2-debian13-r1"]
  contexts = {
    node_22_source = "https://github.com/nodejs/node.git?tag=v22.23.2&checksum=490a9fef8f8adcda5a95bd6f96035b05cb43fe5b"
  }
  args = {
    ATUM_IMAGE_LICENSES = "MIT"
    ATUM_IMAGE_REVISION = "aa4c77582be995286fc6e00aaf530dc7ade102a9"
    ATUM_IMAGE_SOURCE   = "https://github.com/nodejs/node"
    ATUM_IMAGE_TITLE    = "node-toolchain-22"
    ATUM_IMAGE_VERSION  = "22.23.2"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/node-toolchain-22:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/node-toolchain-22:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "node-toolchain-24" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "node-toolchain-24"
  tags       = ["10.77.0.9:32443/atum/node-toolchain:24.19.0-debian13-r1"]
  contexts = {
    node_24_source = "https://github.com/nodejs/node.git?tag=v24.19.0&checksum=1dbab0e88e7ccc6b44c801418911767447796ed0"
  }
  args = {
    ATUM_IMAGE_LICENSES = "MIT"
    ATUM_IMAGE_REVISION = "cdc1b38d40cb567b7ad0b39c86addf830a0af0ae"
    ATUM_IMAGE_SOURCE   = "https://github.com/nodejs/node"
    ATUM_IMAGE_TITLE    = "node-toolchain-24"
    ATUM_IMAGE_VERSION  = "24.19.0"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/node-toolchain-24:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/node-toolchain-24:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "python-toolchain" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "python-toolchain"
  tags       = ["10.77.0.9:32443/atum/python-toolchain:3.12.12-debian13-r1"]
  contexts = {
    python_source = "https://github.com/python/cpython.git?tag=v3.12.12&checksum=32d78678ec9dc36b82bb6194b2fdbdcb97e4b49a"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Python-2.0"
    ATUM_IMAGE_REVISION = "4a5632fbf9bf59477c540e3f53fa7cdbeea3e3f5"
    ATUM_IMAGE_SOURCE   = "https://github.com/python/cpython"
    ATUM_IMAGE_TITLE    = "python-toolchain"
    ATUM_IMAGE_VERSION  = "3.12.12"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/python-toolchain:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/python-toolchain:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "ruby-toolchain" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "ruby-toolchain"
  tags       = ["10.77.0.9:32443/atum/ruby-toolchain:3.3.10-debian13-r1"]
  contexts = {
    jemalloc_source = "https://github.com/jemalloc/jemalloc.git?tag=5.3.0&checksum=cc611be82c57f8f2411347abb96af8c705c972eb"
    ruby_source     = "https://github.com/ruby/ruby.git?tag=v3_3_10&checksum=343ea050023cfc0374fdea6fdf625b2f57b716a4"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Ruby AND BSD-2-Clause"
    ATUM_IMAGE_REVISION = "343ea050023cfc0374fdea6fdf625b2f57b716a4+54eaed1d8b56b1aa528be3bdd1877e59c56fa90c"
    ATUM_IMAGE_SOURCE   = "https://github.com/ruby/ruby;https://github.com/jemalloc/jemalloc"
    ATUM_IMAGE_TITLE    = "ruby-toolchain"
    ATUM_IMAGE_VERSION  = "3.3.10"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/ruby-toolchain:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/ruby-toolchain:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "_buildkit" {
  dockerfile = "docker/Dockerfile.foundation"
  target     = "buildkit"
  tags       = ["10.77.0.9:32443/atum/buildkit:v0.25.2-debian13-r1"]
  contexts = {
    atum_go         = "target:go-toolchain"
    atum_runtime    = "target:debian-runtime"
    buildkit_source = "https://github.com/moby/buildkit.git?tag=v0.25.2&checksum=dcc0fe5e96ae78919b30057d0804c52f13a2eb7e"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "dcc0fe5e96ae78919b30057d0804c52f13a2eb7e"
    ATUM_IMAGE_SOURCE   = "https://github.com/moby/buildkit"
    ATUM_IMAGE_TITLE    = "buildkit"
    ATUM_IMAGE_VERSION  = "0.25.2"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/buildkit:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/buildkit:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "buildkit-bootstrap" {
  inherits   = ["_common", "_buildkit"]
  output     = ["type=cacheonly"]
  cache-from = []
  cache-to   = []
  contexts = {
    atum_go      = "target:go-toolchain-bootstrap"
    atum_runtime = "target:debian-runtime-bootstrap"
  }
}

target "buildkit-bootstrap-publish" {
  inherits   = ["_provenance_only", "_buildkit"]
  output     = [ATUM_BOOTSTRAP_OUTPUT]
  cache-from = []
  cache-to   = []
  contexts = {
    atum_go      = "target:go-toolchain-bootstrap"
    atum_runtime = "target:debian-runtime-bootstrap"
  }
}

target "buildkit" {
  inherits = ["_attested", "_buildkit"]
}

target "_sbom-scanner" {
  dockerfile = "docker/Dockerfile.foundation"
  target     = "sbom-scanner"
  tags       = ["10.77.0.9:32443/atum/sbom-scanner:v1.11.0-debian13-r1"]
  contexts = {
    atum_go             = "target:go-toolchain"
    atum_runtime        = "target:debian-runtime"
    sbom_scanner_source = "https://github.com/docker/buildkit-syft-scanner.git?tag=v1.11.0&checksum=d88056b4e5b61d0ca037340df91be47d343b4386"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "d88056b4e5b61d0ca037340df91be47d343b4386"
    ATUM_IMAGE_SOURCE   = "https://github.com/docker/buildkit-syft-scanner"
    ATUM_IMAGE_TITLE    = "sbom-scanner"
    ATUM_IMAGE_VERSION  = "1.11.0"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/sbom-scanner:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/sbom-scanner:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "sbom-scanner-bootstrap" {
  inherits   = ["_provenance_only", "_sbom-scanner"]
  output     = [ATUM_BOOTSTRAP_OUTPUT]
  cache-from = []
  cache-to   = []
  contexts = {
    atum_go      = "target:go-toolchain-bootstrap"
    atum_runtime = "target:debian-runtime-bootstrap"
  }
}

target "sbom-scanner" {
  inherits = ["_attested", "_sbom-scanner"]
}

target "_build-job" {
  dockerfile = "docker/Dockerfile.foundation"
  target     = "build-job"
  tags       = ["10.77.0.9:32443/atum/build-job:1-debian13-r1"]
  contexts = {
    atum_source       = "../.."
    atum_go           = "target:go-toolchain"
    atum_runtime      = "target:debian-runtime"
    buildx_source     = "https://github.com/docker/buildx.git?tag=v0.30.1&checksum=808fd52a40de3f20c47520bb74df0d49539a5389"
    docker_cli_source = "https://github.com/docker/cli.git?tag=v28.5.2&checksum=9cc6dea35e9a963f281434761c656fba4ac43aed"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0 AND BSD-3-Clause"
    ATUM_IMAGE_REVISION = "7f36edc26d4e3becb6d9c9008ff00f260bb19055+2dc996f71b0ebafb77e64433e58333e049488a3c+ecc694264de6b34e4b59d16245603382f22fa813+9e66234aa13328a5e75b75aa5574e1ca6d6d9c01"
    ATUM_IMAGE_SOURCE   = "https://go.googlesource.com/go;https://github.com/docker/cli;https://github.com/docker/buildx;https://github.com/atum"
    ATUM_IMAGE_TITLE    = "build-job"
    ATUM_IMAGE_VERSION  = "1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/build-job:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/build-job:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "build-job-bootstrap" {
  inherits   = ["_provenance_only", "_build-job"]
  output     = [ATUM_BOOTSTRAP_OUTPUT]
  cache-from = []
  cache-to   = []
  contexts = {
    atum_go      = "target:go-toolchain-bootstrap"
    atum_runtime = "target:debian-runtime-bootstrap"
  }
}

target "build-job" {
  inherits = ["_attested", "_build-job"]
}

target "busybox" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "busybox"
  tags       = ["10.77.0.9:32443/atum/busybox:1.37.0-debian13-r1"]
  contexts = {
    busybox_source = "https://git.busybox.net/busybox.git?tag=1_37_0&checksum=be7d1b7b1701d225379bc1665487ed0871b592a5"
  }
  args = {
    ATUM_IMAGE_LICENSES = "GPL-2.0-only"
    ATUM_IMAGE_REVISION = "be7d1b7b1701d225379bc1665487ed0871b592a5"
    ATUM_IMAGE_SOURCE   = "https://git.busybox.net/busybox"
    ATUM_IMAGE_TITLE    = "busybox"
    ATUM_IMAGE_VERSION  = "1.37.0"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/busybox:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/busybox:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "kubectl-shell" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.foundation"
  target     = "kubectl-shell"
  tags       = ["10.77.0.9:32443/atum/kubectl-shell:v1.36.1-debian13-r1"]
  contexts = {
    atum_go           = "target:go-toolchain"
    atum_runtime      = "target:debian-runtime"
    bash_source       = "https://git.savannah.gnu.org/git/bash.git?tag=bash-5.3&checksum=b8c60bc9ca365f8261fa97900b6fa939f6ebc303"
    kubernetes_source = "https://github.com/kubernetes/kubernetes.git?tag=v1.36.1&checksum=5b824a493a7ca248b726b6ea09d53842b9b992c2"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0 AND GPL-3.0-or-later"
    ATUM_IMAGE_REVISION = "756939600b9a7180fc2df6550a4585b638875e67+b8c60bc9ca365f8261fa97900b6fa939f6ebc303"
    ATUM_IMAGE_SOURCE   = "https://github.com/kubernetes/kubernetes;https://git.savannah.gnu.org/git/bash.git"
    ATUM_IMAGE_TITLE    = "kubectl-shell"
    ATUM_IMAGE_VERSION  = "1.36.1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/kubectl-shell:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/kubectl-shell:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "_go_component" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.component"
  target     = "runtime"
  contexts = {
    atum_go      = "target:go-toolchain"
    atum_runtime = "target:debian-runtime"
  }
}

target "flux-source-controller" {
  inherits = ["_go_component"]
  tags     = ["10.77.0.9:32443/atum/flux-source-controller:v1.8.3-debian13-r1"]
  contexts = { flux_source_controller_source = "https://github.com/fluxcd/source-controller.git?tag=v1.8.3&checksum=694c3a4a6f4f9b0961ab663da5dd4755816c0568" }
  args = {
    ATUM_SOURCE_CONTEXT = "flux_source_controller_source"
    ATUM_BINARY         = "source-controller"
    ATUM_GO_PACKAGE     = "."
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "36331268fa45dad784f15ef085315b3658b1fb4f"
    ATUM_IMAGE_SOURCE   = "https://github.com/fluxcd/source-controller"
    ATUM_IMAGE_TITLE    = "flux-source-controller"
    ATUM_IMAGE_VERSION  = "1.8.3"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-source-controller:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-source-controller:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "flux-kustomize-controller" {
  inherits = ["_go_component"]
  target   = "runtime-git"
  tags     = ["10.77.0.9:32443/atum/flux-kustomize-controller:v1.8.4-debian13-r1"]
  contexts = { flux_kustomize_controller_source = "https://github.com/fluxcd/kustomize-controller.git?tag=v1.8.4&checksum=eff8750a86e6fc32645ce6cd24035fe35dd50a99" }
  args = {
    ATUM_SOURCE_CONTEXT = "flux_kustomize_controller_source"
    ATUM_BINARY         = "kustomize-controller"
    ATUM_GO_PACKAGE     = "."
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "b1937c69bf0ffa69a14d243f46cc270eb152c6d0"
    ATUM_IMAGE_SOURCE   = "https://github.com/fluxcd/kustomize-controller"
    ATUM_IMAGE_TITLE    = "flux-kustomize-controller"
    ATUM_IMAGE_VERSION  = "1.8.4"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-kustomize-controller:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-kustomize-controller:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "flux-helm-controller" {
  inherits = ["_go_component"]
  tags     = ["10.77.0.9:32443/atum/flux-helm-controller:v1.5.4-debian13-r1"]
  contexts = { flux_helm_controller_source = "https://github.com/fluxcd/helm-controller.git?tag=v1.5.4&checksum=5211941473255c3d1ad87d23896ecc7644e85543" }
  args = {
    ATUM_SOURCE_CONTEXT = "flux_helm_controller_source"
    ATUM_BINARY         = "helm-controller"
    ATUM_GO_PACKAGE     = "."
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "e8ee8f10cba72307705ae4cc8e8a8a017c7b3349"
    ATUM_IMAGE_SOURCE   = "https://github.com/fluxcd/helm-controller"
    ATUM_IMAGE_TITLE    = "flux-helm-controller"
    ATUM_IMAGE_VERSION  = "1.5.4"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-helm-controller:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-helm-controller:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "flux-notification-controller" {
  inherits = ["_go_component"]
  tags     = ["10.77.0.9:32443/atum/flux-notification-controller:v1.8.4-debian13-r1"]
  contexts = { flux_notification_controller_source = "https://github.com/fluxcd/notification-controller.git?tag=v1.8.4&checksum=6cc52d47c3bc65b9ae2b2443809fc9d6bdc01749" }
  args = {
    ATUM_SOURCE_CONTEXT = "flux_notification_controller_source"
    ATUM_BINARY         = "notification-controller"
    ATUM_GO_PACKAGE     = "."
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "f98e1eb5aa97adbdbe33018d4b9dd1e47763fad0"
    ATUM_IMAGE_SOURCE   = "https://github.com/fluxcd/notification-controller"
    ATUM_IMAGE_TITLE    = "flux-notification-controller"
    ATUM_IMAGE_VERSION  = "1.8.4"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-notification-controller:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/flux-notification-controller:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "_cert_manager" {
  inherits = ["_go_component"]
  contexts = { cert_manager_source = "https://github.com/cert-manager/cert-manager.git?tag=v1.20.2&checksum=182122142c0876bb34e2301bb9c6faf6de7e0e90" }
  args = {
    ATUM_SOURCE_CONTEXT = "cert_manager_source"
    ATUM_GO_LDFLAGS     = "-s -w -X github.com/cert-manager/cert-manager/pkg/util.AppVersion=v1.20.2 -X github.com/cert-manager/cert-manager/pkg/util.AppGitCommit=e5b7b18450dd2c4b993b95bcd680b1a057205b00"
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "e5b7b18450dd2c4b993b95bcd680b1a057205b00"
    ATUM_IMAGE_SOURCE   = "https://github.com/cert-manager/cert-manager"
    ATUM_IMAGE_VERSION  = "1.20.2"
  }
}

target "cert-manager-controller" {
  inherits = ["_cert_manager"]
  tags     = ["10.77.0.9:32443/atum/cert-manager-controller:v1.20.2-debian13-r1"]
  args = {
    ATUM_BINARY      = "controller"
    ATUM_GO_PACKAGE  = "."
    ATUM_GO_WORKDIR  = "cmd/controller"
    ATUM_IMAGE_TITLE = "cert-manager-controller"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-controller:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-controller:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "cert-manager-webhook" {
  inherits = ["_cert_manager"]
  tags     = ["10.77.0.9:32443/atum/cert-manager-webhook:v1.20.2-debian13-r1"]
  args = {
    ATUM_BINARY      = "webhook"
    ATUM_GO_PACKAGE  = "."
    ATUM_GO_WORKDIR  = "cmd/webhook"
    ATUM_IMAGE_TITLE = "cert-manager-webhook"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-webhook:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-webhook:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "cert-manager-cainjector" {
  inherits = ["_cert_manager"]
  target   = "runtime-procps"
  tags     = ["10.77.0.9:32443/atum/cert-manager-cainjector:v1.20.2-debian13-r1"]
  args = {
    ATUM_BINARY      = "cainjector"
    ATUM_GO_PACKAGE  = "."
    ATUM_GO_WORKDIR  = "cmd/cainjector"
    ATUM_IMAGE_TITLE = "cert-manager-cainjector"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-cainjector:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-cainjector:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "cert-manager-startupapicheck" {
  inherits = ["_cert_manager"]
  tags     = ["10.77.0.9:32443/atum/cert-manager-startupapicheck:v1.20.2-debian13-r1"]
  args = {
    ATUM_BINARY      = "startupapicheck"
    ATUM_GO_PACKAGE  = "."
    ATUM_GO_WORKDIR  = "cmd/startupapicheck"
    ATUM_IMAGE_TITLE = "cert-manager-startupapicheck"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-startupapicheck:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-startupapicheck:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "cert-manager-acmesolver" {
  inherits = ["_cert_manager"]
  tags     = ["10.77.0.9:32443/atum/cert-manager-acmesolver:v1.20.2-debian13-r1"]
  args = {
    ATUM_BINARY      = "acmesolver"
    ATUM_GO_PACKAGE  = "."
    ATUM_GO_WORKDIR  = "cmd/acmesolver"
    ATUM_IMAGE_TITLE = "cert-manager-acmesolver"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-acmesolver:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/cert-manager-acmesolver:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "_harbor" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.harbor"
  contexts = {
    atum_go           = "target:go-toolchain"
    atum_node         = "target:node-toolchain-22"
    atum_runtime      = "target:debian-runtime"
    go_swagger_source = "https://github.com/go-swagger/go-swagger.git?tag=v0.33.1&checksum=2af7725271cf99ace5d44ab134acb53bffcc5734"
    harbor_source     = "https://github.com/goharbor/harbor.git?tag=v2.15.1&checksum=335c05f2b9507b4c7116fe69b84e31ef9f4b91dd"
  }
  args = {
    ATUM_IMAGE_VERSION = "2.15.1"
  }
}

target "_harbor_nginx" {
  inherits = ["_harbor"]
  contexts = { nginx_source = "https://github.com/nginx/nginx.git?tag=release-1.28.0&checksum=f6f8d515885fcda20f09b83583d576337fbabe0a" }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0 AND BSD-2-Clause"
    ATUM_IMAGE_REVISION = "335c05f2b9507b4c7116fe69b84e31ef9f4b91dd+481d28cb4e04c8096b9b6134856891dc52ecc68f"
    ATUM_IMAGE_SOURCE   = "https://github.com/goharbor/harbor;https://github.com/nginx/nginx"
  }
}

target "harbor-nginx" {
  inherits   = ["_harbor_nginx"]
  target     = "harbor-nginx"
  tags       = ["10.77.0.9:32443/atum/harbor-nginx:v2.15.1-debian13-r1"]
  contexts   = { atum_node = "target:debian-runtime" }
  args       = { ATUM_IMAGE_TITLE = "harbor-nginx" }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-nginx:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-nginx:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "harbor-portal" {
  inherits   = ["_harbor_nginx"]
  target     = "harbor-portal"
  tags       = ["10.77.0.9:32443/atum/harbor-portal:v2.15.1-debian13-r1"]
  args       = { ATUM_IMAGE_TITLE = "harbor-portal" }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-portal:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-portal:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "_harbor_service" {
  inherits = ["_harbor"]
  contexts = { atum_node = "target:debian-runtime" }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "335c05f2b9507b4c7116fe69b84e31ef9f4b91dd+2af7725271cf99ace5d44ab134acb53bffcc5734"
    ATUM_IMAGE_SOURCE   = "https://github.com/goharbor/harbor;https://github.com/go-swagger/go-swagger"
  }
}

target "harbor-core" {
  inherits   = ["_harbor_service"]
  target     = "harbor-core"
  tags       = ["10.77.0.9:32443/atum/harbor-core:v2.15.1-debian13-r1"]
  args       = { ATUM_IMAGE_TITLE = "harbor-core" }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-core:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-core:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "harbor-jobservice" {
  inherits   = ["_harbor_service"]
  target     = "harbor-jobservice"
  tags       = ["10.77.0.9:32443/atum/harbor-jobservice:v2.15.1-debian13-r1"]
  args       = { ATUM_IMAGE_TITLE = "harbor-jobservice" }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-jobservice:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-jobservice:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "_harbor_distribution" {
  inherits = ["_harbor"]
  contexts = {
    atum_node           = "target:debian-runtime"
    distribution_source = "https://github.com/goharbor/distribution.git?tag=v2.8.3-harbor.1-rc.1&checksum=086d3c33b3981cf598d0d82336a907fcf5c4c848"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "335c05f2b9507b4c7116fe69b84e31ef9f4b91dd+086d3c33b3981cf598d0d82336a907fcf5c4c848"
    ATUM_IMAGE_SOURCE   = "https://github.com/goharbor/harbor;https://github.com/goharbor/distribution"
  }
}

target "harbor-registry" {
  inherits   = ["_harbor_distribution"]
  target     = "harbor-registry"
  tags       = ["10.77.0.9:32443/atum/harbor-registry:v2.15.1-debian13-r1"]
  args       = { ATUM_IMAGE_TITLE = "harbor-registry" }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-registry:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-registry:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "harbor-registryctl" {
  inherits   = ["_harbor_distribution"]
  target     = "harbor-registryctl"
  tags       = ["10.77.0.9:32443/atum/harbor-registryctl:v2.15.1-debian13-r1"]
  args       = { ATUM_IMAGE_TITLE = "harbor-registryctl" }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-registryctl:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-registryctl:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "harbor-database" {
  inherits = ["_harbor"]
  target   = "harbor-database"
  tags     = ["10.77.0.9:32443/atum/harbor-database:18.3-debian13-r1"]
  contexts = {
    atum_node            = "target:debian-runtime"
    postgresql_15_source = "https://github.com/postgres/postgres.git?tag=REL_15_18&checksum=005c1971a2926fbb9caf5a1ad634cd17a42bfd3c"
    postgresql_18_source = "https://github.com/postgres/postgres.git?tag=REL_18_3&checksum=62d6c7d3df6287f1bd83199c1a746e50d31571a0"
  }
  args = {
    ATUM_IMAGE_LICENSES = "PostgreSQL AND Apache-2.0"
    ATUM_IMAGE_REVISION = "005c1971a2926fbb9caf5a1ad634cd17a42bfd3c+62d6c7d3df6287f1bd83199c1a746e50d31571a0+335c05f2b9507b4c7116fe69b84e31ef9f4b91dd"
    ATUM_IMAGE_SOURCE   = "https://github.com/postgres/postgres;https://github.com/goharbor/harbor"
    ATUM_IMAGE_TITLE    = "harbor-database"
    ATUM_IMAGE_VERSION  = "18.3"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-database:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-database:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "harbor-redis" {
  inherits = ["_harbor"]
  target   = "harbor-redis"
  tags     = ["10.77.0.9:32443/atum/harbor-redis:8.6.1-debian13-r1"]
  contexts = {
    atum_node    = "target:debian-runtime"
    redis_source = "https://github.com/redis/redis.git?tag=8.6.1&checksum=aaaea63b235e8a7b42e7905725c3976bc75fdd55"
  }
  args = {
    ATUM_IMAGE_LICENSES = "AGPL-3.0-only AND Apache-2.0"
    ATUM_IMAGE_REVISION = "aaaea63b235e8a7b42e7905725c3976bc75fdd55+335c05f2b9507b4c7116fe69b84e31ef9f4b91dd"
    ATUM_IMAGE_SOURCE   = "https://github.com/redis/redis;https://github.com/goharbor/harbor"
    ATUM_IMAGE_TITLE    = "harbor-redis"
    ATUM_IMAGE_VERSION  = "8.6.1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-redis:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/harbor-redis:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "authservice" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.authservice"
  target     = "authservice"
  tags       = ["10.77.0.9:32443/atum/authservice:1.1.6-debian13-r1"]
  contexts = {
    atum_go            = "target:go-toolchain"
    atum_runtime       = "target:debian-runtime"
    authservice_source = "https://github.com/istio-ecosystem/authservice.git?tag=v1.1.6&checksum=7ff3c84ce0c9736213183f994873159eb84a36e3"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "02b7dfbd5668fbf1ac25988326d6e3632a444c6a"
    ATUM_IMAGE_SOURCE   = "https://github.com/istio-ecosystem/authservice"
    ATUM_IMAGE_TITLE    = "authservice"
    ATUM_IMAGE_VERSION  = "1.1.6"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/authservice:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/authservice:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "mesh" {
  name = item.name
  matrix = {
    item = [
      {
        name     = "istio-pilot"
        version  = "1.29.2"
        tag      = "10.77.0.9:32443/atum/istio-pilot:1.29.2-debian13-r1"
        licenses = "Apache-2.0"
        revision = "0c774325b938c4dbda4ea4ad4fb6156e80a12de8"
        source   = "https://github.com/istio/istio"
      },
      {
        name     = "istio-proxy"
        version  = "1.29.2"
        tag      = "10.77.0.9:32443/atum/istio-proxy:1.29.2-debian13-r1"
        licenses = "Apache-2.0 AND X11"
        revision = "0c774325b938c4dbda4ea4ad4fb6156e80a12de8+af30be60b7c35f2aceaea1b7382c7fbf12aa5e67+79b9071f2be20a24c7be031655a5638f6032f29f"
        source   = "https://github.com/istio/istio;https://github.com/istio/proxy;https://github.com/mirror/ncurses"
      },
      {
        name     = "kiali-operator"
        version  = "2.25.0"
        tag      = "10.77.0.9:32443/atum/kiali-operator:v2.25.0-debian13-r1"
        licenses = "Apache-2.0 AND GPL-3.0-or-later"
        revision = "c11342e8d01f45cc274dd399142af419e09e1685+42b5d80c75f1ddda8f2dbe1629b9454d366a8d6a+80243f818078ebd263ca27f6e83812c8af26d7ba+f22ffcab184680f8a407c9b2b199ba6235ac1d27+88bbc507e2eddbc7da6625acf1cb6252cb3577b2+31376a3ee6bda4ff735ce43bf76e808a6593873f"
        source   = "https://github.com/kiali/kiali-operator;https://github.com/operator-framework/ansible-operator-plugins;https://github.com/ansible-collections/community.general;https://github.com/ansible-collections/kubernetes.core;https://github.com/operator-framework/operator-sdk-ansible-util;https://github.com/ansible-collections/ansible.posix"
      },
      {
        name     = "kiali-server"
        version  = "2.25.0"
        tag      = "10.77.0.9:32443/atum/kiali-server:v2.25.0-debian13-r1"
        licenses = "Apache-2.0"
        revision = "3292851b81f45968bcce5a7da6afad880bdf67d6"
        source   = "https://github.com/kiali/kiali"
      },
    ]
  }
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.mesh"
  target     = item.name
  tags       = [item.tag]
  contexts = {
    ansible_community_general_source = "https://github.com/ansible-collections/community.general.git?tag=9.0.0&checksum=80243f818078ebd263ca27f6e83812c8af26d7ba"
    ansible_kubernetes_core_source   = "https://github.com/ansible-collections/kubernetes.core.git?tag=4.0.0&checksum=e988abed821e9ee5bf417e3d3db875e98e6e8336"
    ansible_operator_source          = "https://github.com/operator-framework/ansible-operator-plugins.git?tag=v1.35.0&checksum=7ebf846ab50117eea530fd133b1b255214ba7a28"
    ansible_operator_util_source     = "https://github.com/operator-framework/operator-sdk-ansible-util.git?tag=v0.5.0&checksum=ed13ada4ce6d70febd6f734d3c34b6f47de39995"
    ansible_posix_source             = "https://github.com/ansible-collections/ansible.posix.git?tag=1.6.2&checksum=784066fe629c4ea18cefdf6a383351c8a757009b"
    atum_go                          = "target:go-toolchain"
    atum_node                        = item.name == "kiali-server" ? "target:node-toolchain-24" : "target:debian-runtime"
    atum_python                      = item.name == "kiali-operator" ? "target:python-toolchain" : "target:debian-runtime"
    atum_runtime                     = "target:debian-runtime"
    istio_proxy_source               = "https://github.com/istio/proxy.git?tag=1.29.2&checksum=791aaf76cf88d8f1767199d46e711468a3c0045a"
    istio_source                     = "https://github.com/istio/istio.git?tag=1.29.2&checksum=5c9e58b03ec3dd5ae1c87dba463d7388e0792fb8"
    kiali_operator_source            = "https://github.com/kiali/kiali-operator.git?tag=v2.25.0&checksum=c11342e8d01f45cc274dd399142af419e09e1685"
    kiali_source                     = "https://github.com/kiali/kiali.git?tag=v2.25.0&checksum=3292851b81f45968bcce5a7da6afad880bdf67d6"
    ncurses_source                   = "https://github.com/mirror/ncurses.git?tag=v6.4&checksum=79b9071f2be20a24c7be031655a5638f6032f29f"
  }
  args = {
    ATUM_IMAGE_LICENSES = item.licenses
    ATUM_IMAGE_REVISION = item.revision
    ATUM_IMAGE_SOURCE   = item.source
    ATUM_IMAGE_TITLE    = item.name
    ATUM_IMAGE_VERSION  = item.version
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "policy" {
  name = item.name
  matrix = {
    item = [
      { name = "kyverno-admission-controller", version = "1.17.1", tag = "10.77.0.9:32443/atum/kyverno-admission-controller:v1.17.1-debian13-r1", licenses = "Apache-2.0", revision = "0fe91382401630df2c26c5525dd9eb9c0df1b0ef", source = "https://github.com/kyverno/kyverno" },
      { name = "kyverno-preflight", version = "1.17.1", tag = "10.77.0.9:32443/atum/kyverno-preflight:v1.17.1-debian13-r1", licenses = "Apache-2.0", revision = "0fe91382401630df2c26c5525dd9eb9c0df1b0ef", source = "https://github.com/kyverno/kyverno" },
      { name = "kyverno-cli", version = "1.17.1", tag = "10.77.0.9:32443/atum/kyverno-cli:v1.17.1-debian13-r1", licenses = "Apache-2.0", revision = "0fe91382401630df2c26c5525dd9eb9c0df1b0ef", source = "https://github.com/kyverno/kyverno" },
      { name = "kyverno-background-controller", version = "1.17.1", tag = "10.77.0.9:32443/atum/kyverno-background-controller:v1.17.1-debian13-r1", licenses = "Apache-2.0", revision = "0fe91382401630df2c26c5525dd9eb9c0df1b0ef", source = "https://github.com/kyverno/kyverno" },
      { name = "kyverno-cleanup-controller", version = "1.17.1", tag = "10.77.0.9:32443/atum/kyverno-cleanup-controller:v1.17.1-debian13-r1", licenses = "Apache-2.0", revision = "0fe91382401630df2c26c5525dd9eb9c0df1b0ef", source = "https://github.com/kyverno/kyverno" },
      { name = "kyverno-reports-controller", version = "1.17.1", tag = "10.77.0.9:32443/atum/kyverno-reports-controller:v1.17.1-debian13-r1", licenses = "Apache-2.0", revision = "0fe91382401630df2c26c5525dd9eb9c0df1b0ef", source = "https://github.com/kyverno/kyverno" },
      { name = "kyverno-readiness-checker", version = "0.1.0", tag = "10.77.0.9:32443/atum/kyverno-readiness-checker:v0.1.0-debian13-r1", licenses = "Apache-2.0", revision = "0fe91382401630df2c26c5525dd9eb9c0df1b0ef", source = "https://github.com/kyverno/kyverno" },
      { name = "policy-reporter", version = "3.7.3", tag = "10.77.0.9:32443/atum/policy-reporter:3.7.3-debian13-r1", licenses = "MIT", revision = "72919fd607f16b4383fa698470ddb7c011b92e0a", source = "https://github.com/kyverno/policy-reporter" },
      { name = "policy-reporter-ui", version = "2.5.1", tag = "10.77.0.9:32443/atum/policy-reporter-ui:2.5.1-debian13-r1", licenses = "MIT", revision = "a1acbeaf5cf74ddc986d36cd41bf9332777fc67e", source = "https://github.com/kyverno/policy-reporter-ui" },
      { name = "policy-reporter-kyverno-plugin", version = "0.6.0", tag = "10.77.0.9:32443/atum/policy-reporter-kyverno-plugin:0.6.0-debian13-r1", licenses = "Apache-2.0", revision = "7040b48afb27b5be628d588adc9428bcb3371385", source = "https://github.com/kyverno/policy-reporter-plugins" },
      { name = "kube-webhook-certgen", version = "1.6.9", tag = "10.77.0.9:32443/atum/kube-webhook-certgen:v1.6.9-debian13-r1", licenses = "Apache-2.0", revision = "0a5901f3c64f11e92e487799b8da3f00cca37515", source = "https://github.com/kubernetes/ingress-nginx" },
    ]
  }
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.policy"
  target     = item.name
  tags       = [item.tag]
  contexts = {
    atum_go                       = "target:go-toolchain"
    atum_runtime                  = "target:debian-runtime"
    ingress_nginx_source          = "https://github.com/kubernetes/ingress-nginx.git?tag=controller-v1.15.1&checksum=0a5901f3c64f11e92e487799b8da3f00cca37515"
    kyverno_source                = "https://github.com/kyverno/kyverno.git?tag=v1.17.1&checksum=be5e7d7eac29abe54ebda8a1028664c54e50897e"
    policy_reporter_plugin_source = "https://github.com/kyverno/policy-reporter-plugins.git?tag=kyverno-plugin-v0.6.0&checksum=7040b48afb27b5be628d588adc9428bcb3371385"
    policy_reporter_source        = "https://github.com/kyverno/policy-reporter.git?tag=v3.7.3&checksum=72919fd607f16b4383fa698470ddb7c011b92e0a"
    policy_reporter_ui_source     = "https://github.com/kyverno/policy-reporter-ui.git?tag=v2.5.1&checksum=a1acbeaf5cf74ddc986d36cd41bf9332777fc67e"
  }
  args = {
    ATUM_IMAGE_LICENSES = item.licenses
    ATUM_IMAGE_REVISION = item.revision
    ATUM_IMAGE_SOURCE   = item.source
    ATUM_IMAGE_TITLE    = item.name
    ATUM_IMAGE_VERSION  = item.version
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "observability" {
  name = item.name
  matrix = {
    item = [
      { name = "fluent-bit", version = "5.0.6", tag = "10.77.0.9:32443/atum/fluent-bit:5.0.6-debian13-r1", licenses = "Apache-2.0", revision = "7b3a43645dcf41fce38ac4e72b1e9e2f7641b027", source = "https://github.com/fluent/fluent-bit" },
      { name = "configmap-reload", version = "0.15.0", tag = "10.77.0.9:32443/atum/configmap-reload:v0.15.0-debian13-r1", licenses = "Apache-2.0", revision = "3f1e9babda3b94b235d203712c17cb88c53d43d8", source = "https://github.com/jimmidyson/configmap-reload" },
      { name = "tempo", version = "2.10.1", tag = "10.77.0.9:32443/atum/tempo:2.10.1-debian13-r1", licenses = "AGPL-3.0-only", revision = "f3dd275820487ab5aebe42ddd96203665da2d453", source = "https://github.com/grafana/tempo" },
      { name = "prometheus", version = "3.11.1", tag = "10.77.0.9:32443/atum/prometheus:v3.11.1-debian13-r1", licenses = "Apache-2.0", revision = "1bd2f3a9fdedf52e6f613449cc4c50e86ca24676", source = "https://github.com/prometheus/prometheus" },
      { name = "alertmanager", version = "0.32.0", tag = "10.77.0.9:32443/atum/alertmanager:v0.32.0-debian13-r1", licenses = "Apache-2.0", revision = "685a2a1c6bb01b2c17bc1bfae995cb3416c1115e", source = "https://github.com/prometheus/alertmanager" },
      { name = "prometheus-operator", version = "0.90.1", tag = "10.77.0.9:32443/atum/prometheus-operator:v0.90.1-debian13-r1", licenses = "Apache-2.0", revision = "32d1b3dfa05d070762450efe9624bb2483c782be", source = "https://github.com/prometheus-operator/prometheus-operator" },
      { name = "prometheus-config-reloader", version = "0.90.1", tag = "10.77.0.9:32443/atum/prometheus-config-reloader:v0.90.1-debian13-r1", licenses = "Apache-2.0", revision = "32d1b3dfa05d070762450efe9624bb2483c782be", source = "https://github.com/prometheus-operator/prometheus-operator" },
      { name = "thanos", version = "0.41.0", tag = "10.77.0.9:32443/atum/thanos:v0.41.0-debian13-r1", licenses = "Apache-2.0", revision = "cb1396b916241f63fff75e4f5362ea65f18f2303", source = "https://github.com/thanos-io/thanos" },
      { name = "kube-state-metrics", version = "2.18.0", tag = "10.77.0.9:32443/atum/kube-state-metrics:v2.18.0-debian13-r1", licenses = "Apache-2.0", revision = "ab562f78ebf4cb97cc2f87c1235e457076035d16", source = "https://github.com/kubernetes/kube-state-metrics" },
      { name = "node-exporter", version = "1.11.1", tag = "10.77.0.9:32443/atum/node-exporter:v1.11.1-debian13-r1", licenses = "Apache-2.0", revision = "0dd664dece3f8319f6bec5a221acd2c7ad13a23d", source = "https://github.com/prometheus/node_exporter" },
      { name = "grafana", version = "12.4.2", tag = "10.77.0.9:32443/atum/grafana:12.4.2-debian13-r1", licenses = "AGPL-3.0-only", revision = "ebade4c739e1aface4ce094934ad85374887a680", source = "https://github.com/grafana/grafana" },
      { name = "k8s-sidecar", version = "2.5.4", tag = "10.77.0.9:32443/atum/k8s-sidecar:2.5.4-debian13-r1", licenses = "MIT", revision = "465b4914235515e18d2e6c21cfa05e090b77715c", source = "https://github.com/kiwigrid/k8s-sidecar" },
    ]
  }
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.observability"
  target     = item.name
  tags       = [item.tag]
  contexts = {
    alertmanager_source        = "https://github.com/prometheus/alertmanager.git?tag=v0.32.0&checksum=53dc36c2dd396117f742d18d0967f197c267534d"
    atum_go                    = item.name == "fluent-bit" || item.name == "k8s-sidecar" ? "target:debian-runtime" : "target:go-toolchain"
    atum_node                  = item.name == "grafana" || item.name == "alertmanager" ? "target:node-toolchain-24" : item.name == "prometheus" ? "target:node-toolchain-22" : "target:debian-runtime"
    atum_python                = item.name == "k8s-sidecar" ? "target:python-toolchain" : "target:debian-runtime"
    atum_runtime               = "target:debian-runtime"
    configmap_reload_source    = "https://github.com/jimmidyson/configmap-reload.git?tag=v0.15.0&checksum=c9ce4e6fad81609dfb22a3156b9eefb7f14bd2c0"
    fluent_bit_source          = "https://github.com/fluent/fluent-bit.git?tag=v5.0.6&checksum=7b3a43645dcf41fce38ac4e72b1e9e2f7641b027"
    grafana_source             = "https://github.com/grafana/grafana.git?tag=v12.4.2&checksum=e1a388acfcca72251174028e8b89efa0c149fea8"
    k8s_sidecar_source         = "https://github.com/kiwigrid/k8s-sidecar.git?tag=2.5.4&checksum=465b4914235515e18d2e6c21cfa05e090b77715c"
    kube_state_metrics_source  = "https://github.com/kubernetes/kube-state-metrics.git?tag=v2.18.0&checksum=ab562f78ebf4cb97cc2f87c1235e457076035d16"
    node_exporter_source       = "https://github.com/prometheus/node_exporter.git?tag=v1.11.1&checksum=e9ef753cb1dafeb0dac304ff242425efe5f7a429"
    prometheus_operator_source = "https://github.com/prometheus-operator/prometheus-operator.git?tag=v0.90.1&checksum=5f2b2cedbb61693c7d2e0960426eda879d177007"
    prometheus_source          = "https://github.com/prometheus/prometheus.git?tag=v3.11.1&checksum=f750a44404a5fd01368090111279be56af37dbe5"
    tempo_source               = "https://github.com/grafana/tempo.git?tag=v2.10.1&checksum=26fb6a243abd00ca70cafd8e1969f6911076347d"
    thanos_source              = "https://github.com/thanos-io/thanos.git?tag=v0.41.0&checksum=f89ca2aff253fd33334b5db3a2c7d4ed508a70d3"
  }
  args = {
    ATUM_IMAGE_LICENSES = item.licenses
    ATUM_IMAGE_REVISION = item.revision
    ATUM_IMAGE_SOURCE   = item.source
    ATUM_IMAGE_TITLE    = item.name
    ATUM_IMAGE_VERSION  = item.version
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "data-security" {
  name = item.name
  matrix = {
    item = [
      { name = "keycloak", version = "26.6.1", tag = "10.77.0.9:32443/atum/keycloak:26.6.1-debian13-r1", licenses = "Apache-2.0", revision = "5bebfac09dd9abc5fe8b43f00ac596f0a5c998d1", source = "https://github.com/keycloak/keycloak" },
      { name = "postgresql-17", version = "17.4", tag = "10.77.0.9:32443/atum/postgresql:17.4-debian13-r1", licenses = "PostgreSQL", revision = "f8554dee417ffc4540c94cf357f7bf7d4b6e5d80", source = "https://github.com/postgres/postgres" },
      { name = "postgresql-18", version = "18.3", tag = "10.77.0.9:32443/atum/postgresql:18.3-debian13-r1", licenses = "PostgreSQL", revision = "62d6c7d3df6287f1bd83199c1a746e50d31571a0", source = "https://github.com/postgres/postgres" },
      { name = "redis-8-4", version = "8.4.0", tag = "10.77.0.9:32443/atum/redis:8.4.0-debian13-r1", licenses = "AGPL-3.0-only", revision = "60ba86f3c8b4e1ec96451171753a0a38e5c45a0c", source = "https://github.com/redis/redis" },
      { name = "redis-exporter", version = "1.86.0", tag = "10.77.0.9:32443/atum/redis-exporter:v1.86.0", licenses = "MIT", revision = "c4dac6ba37ea9c7da7652beb329612af977106aa", source = "https://github.com/oliver006/redis_exporter" },
      { name = "minio", version = "2024-06-04", tag = "10.77.0.9:32443/atum/minio:RELEASE.2024-06-04T19-20-08Z-debian13-r1", licenses = "AGPL-3.0-only", revision = "17fe91d6d162b3ad372760726d29f1f348dbdb09", source = "https://github.com/minio/minio" },
      { name = "minio-client", version = "2024-10-02", tag = "10.77.0.9:32443/atum/minio-client:RELEASE.2024-10-02T08-27-28Z-debian13-r1", licenses = "AGPL-3.0-only", revision = "ce0b4341521de16ae2172d42054bbe054f9c9651", source = "https://github.com/minio/mc" },
      { name = "openbao", version = "2.5.3", tag = "10.77.0.9:32443/atum/openbao:2.5.3-debian13-r1", licenses = "MPL-2.0", revision = "988c88d7ef54b4d4581629b229488dfba5e085ba", source = "https://github.com/openbao/openbao" },
      { name = "velero", version = "1.18.0", tag = "10.77.0.9:32443/atum/velero:v1.18.0-debian13-r1", licenses = "Apache-2.0", revision = "6adcf06b5b0e6fb93998d3e101e2cbdc134fa3c3", source = "https://github.com/vmware-tanzu/velero" },
      { name = "velero-aws", version = "1.14.0", tag = "10.77.0.9:32443/atum/velero-plugin-for-aws:v1.14.0-debian13-r1", licenses = "Apache-2.0", revision = "2a52b1296d4e5c6deebc444430f795f960a7bd1e", source = "https://github.com/vmware-tanzu/velero-plugin-for-aws" },
    ]
  }
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.data"
  target     = item.name
  tags       = [item.tag]
  contexts = {
    atum_go               = item.name == "redis-exporter" || item.name == "minio" || item.name == "minio-client" || item.name == "openbao" || item.name == "vault-k8s" || item.name == "velero" || item.name == "velero-aws" ? "target:go-toolchain" : "target:debian-runtime"
    atum_node             = item.name == "opensearch-dashboards" ? "target:node-toolchain-22" : "target:debian-runtime"
    atum_node_20          = item.name == "openbao" ? "target:node-toolchain-20" : "target:debian-runtime"
    atum_runtime          = "target:debian-runtime"
    keycloak_source       = "https://github.com/keycloak/keycloak.git?tag=26.6.1&checksum=5bebfac09dd9abc5fe8b43f00ac596f0a5c998d1"
    minio_client_source   = "https://github.com/minio/mc.git?tag=RELEASE.2024-10-02T08-27-28Z&checksum=277d365c42b656d581c8711ba985674f242b92e7"
    minio_source          = "https://github.com/minio/minio.git?tag=RELEASE.2024-06-04T19-20-08Z&checksum=497742026305e0152dd6f3fbf3cbd74c36ad817f"
    openbao_source        = "https://github.com/openbao/openbao.git?tag=v2.5.3&checksum=988c88d7ef54b4d4581629b229488dfba5e085ba"
    postgresql_17_source  = "https://github.com/postgres/postgres.git?tag=REL_17_4&checksum=f8554dee417ffc4540c94cf357f7bf7d4b6e5d80"
    postgresql_18_source  = "https://github.com/postgres/postgres.git?tag=REL_18_3&checksum=62d6c7d3df6287f1bd83199c1a746e50d31571a0"
    redis_8_4_source      = "https://github.com/redis/redis.git?tag=8.4.0&checksum=60ba86f3c8b4e1ec96451171753a0a38e5c45a0c"
    redis_exporter_source = "https://github.com/oliver006/redis_exporter.git?tag=v1.86.0&checksum=c4dac6ba37ea9c7da7652beb329612af977106aa"
    velero_aws_source     = "https://github.com/vmware-tanzu/velero-plugin-for-aws.git?tag=v1.14.0&checksum=2a52b1296d4e5c6deebc444430f795f960a7bd1e"
    velero_source         = "https://github.com/vmware-tanzu/velero.git?tag=v1.18.0&checksum=6adcf06b5b0e6fb93998d3e101e2cbdc134fa3c3"
  }
  args = {
    ATUM_IMAGE_LICENSES = item.licenses
    ATUM_IMAGE_REVISION = item.revision
    ATUM_IMAGE_SOURCE   = item.source
    ATUM_IMAGE_TITLE    = item.name
    ATUM_IMAGE_VERSION  = item.version
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "opensearch-operator" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.data"
  target     = "opensearch-operator"
  tags       = ["10.77.0.9:32443/atum/opensearch-operator:2.8.0-debian13-r1"]
  contexts = {
    atum_go                    = "target:go-toolchain"
    atum_node                  = "target:debian-runtime"
    atum_node_20               = "target:debian-runtime"
    atum_runtime               = "target:debian-runtime"
    opensearch_operator_source = "https://github.com/opensearch-project/opensearch-k8s-operator.git?tag=v2.8.0&checksum=7fdc6cfa562ce098b0da42c13cc18a9dbd6373ce"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "7fdc6cfa562ce098b0da42c13cc18a9dbd6373ce"
    ATUM_IMAGE_SOURCE   = "https://github.com/opensearch-project/opensearch-k8s-operator"
    ATUM_IMAGE_TITLE    = "opensearch-operator"
    ATUM_IMAGE_VERSION  = "2.8.0"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/opensearch-operator:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/opensearch-operator:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "bigbang-harbor-redis" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.data"
  target     = "bigbang-harbor-redis"
  tags       = ["10.77.0.9:32443/atum/redis:8.8.1-debian13-r1"]
  contexts = {
    atum_runtime = "target:debian-runtime"
    redis_source = "https://github.com/redis/redis.git?tag=8.8.1&checksum=77b6c308396c9700672390a210143a8496fb4b10"
  }
  args = {
    ATUM_IMAGE_LICENSES = "AGPL-3.0-only"
    ATUM_IMAGE_REVISION = "77b6c308396c9700672390a210143a8496fb4b10"
    ATUM_IMAGE_SOURCE   = "https://github.com/redis/redis"
    ATUM_IMAGE_TITLE    = "bigbang-harbor-redis"
    ATUM_IMAGE_VERSION  = "8.8.1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/bigbang-harbor-redis:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/bigbang-harbor-redis:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "vault-k8s" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.data"
  target     = "vault-k8s"
  tags       = ["10.77.0.9:32443/atum/vault-k8s:1.7.5-debian13-r1"]
  contexts = {
    atum_go          = "target:go-toolchain"
    atum_runtime     = "target:debian-runtime"
    vault_k8s_source = "https://github.com/hashicorp/vault-k8s.git?tag=v1.7.5&checksum=7efae2b937dc412dc34055bee697bcff9a7392b4"
  }
  args = {
    ATUM_IMAGE_LICENSES = "MPL-2.0"
    ATUM_IMAGE_REVISION = "7efae2b937dc412dc34055bee697bcff9a7392b4"
    ATUM_IMAGE_SOURCE   = "https://github.com/hashicorp/vault-k8s"
    ATUM_IMAGE_TITLE    = "vault-k8s"
    ATUM_IMAGE_VERSION  = "1.7.5"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/vault-k8s:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/vault-k8s:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "opensearch" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.data"
  target     = "opensearch"
  tags       = ["10.77.0.9:32443/atum/opensearch:3.8.0-debian13-r1"]
  contexts = {
    atum_runtime      = "target:debian-runtime"
    opensearch_source = "https://github.com/opensearch-project/OpenSearch.git?tag=3.8.0&checksum=e5a3c5691be87af6c12dbe3e158c59c04ee72973"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "e5a3c5691be87af6c12dbe3e158c59c04ee72973"
    ATUM_IMAGE_SOURCE   = "https://github.com/opensearch-project/OpenSearch"
    ATUM_IMAGE_TITLE    = "opensearch"
    ATUM_IMAGE_VERSION  = "3.8.0"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/opensearch:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/opensearch:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "opensearch-dashboards" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.data"
  target     = "opensearch-dashboards"
  tags       = ["10.77.0.9:32443/atum/opensearch-dashboards:3.8.0-debian13-r1"]
  contexts = {
    atum_node                    = "target:node-toolchain-22"
    atum_runtime                 = "target:debian-runtime"
    opensearch_dashboards_source = "https://github.com/opensearch-project/OpenSearch-Dashboards.git?tag=3.8.0&checksum=aa72a9818a045ad4e290a5eb9be59e025b90634d"
  }
  args = {
    ATUM_IMAGE_LICENSES = "Apache-2.0"
    ATUM_IMAGE_REVISION = "aa72a9818a045ad4e290a5eb9be59e025b90634d"
    ATUM_IMAGE_SOURCE   = "https://github.com/opensearch-project/OpenSearch-Dashboards"
    ATUM_IMAGE_TITLE    = "opensearch-dashboards"
    ATUM_IMAGE_VERSION  = "3.8.0"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/opensearch-dashboards:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/opensearch-dashboards:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "_gitlab_sources" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.gitlab"
  contexts = {
    atum_go                   = "target:go-toolchain"
    atum_node                 = "target:node-toolchain-22"
    atum_postgresql           = "target:postgresql-17"
    atum_python               = "target:python-toolchain"
    atum_ruby                 = "target:ruby-toolchain"
    atum_runtime              = "target:debian-runtime"
    cfssl_source              = "https://github.com/cloudflare/cfssl.git?tag=v1.6.1&checksum=50bc69f56965e5ac81d2c27225769b3220e90080"
    container_registry_source = "https://gitlab.com/gitlab-org/container-registry.git?tag=v4.39.0-gitlab&checksum=9a519e5f0e01acf419eed44ec31f474d26882781"
    gitaly_source             = "https://gitlab.com/gitlab-org/gitaly.git?tag=v18.11.1&checksum=561e87782d7a5762f6bb30992ee0081cabfa280c"
    gitlab_cng_source         = "https://gitlab.com/gitlab-org/build/CNG.git?tag=v18.11.1&checksum=c03d2840312ad5d868ec221a3c112497189977ce"
    gitlab_exporter_source    = "https://gitlab.com/gitlab-org/gitlab-exporter.git?tag=16.7.0&checksum=633101da6e62b1ece051f8762bd89ffaacace6f0"
    gitlab_foss_source        = "https://gitlab.com/gitlab-org/gitlab-foss.git?tag=v18.11.1&checksum=1dfc640ddc4db26d9ee7af716cff8a0d097d359c"
    gitlab_gomplate_source    = "https://github.com/hairyhenderson/gomplate.git?tag=v5.0.0&checksum=8eba961bb4e69acf85f6c3205196378967c14ef1"
    gitlab_kas_source         = "https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent.git?tag=v18.11.1&checksum=664d39a0b3b67fd5ae23c2568fcaa1ea80f985a6"
    gitlab_logger_source      = "https://gitlab.com/gitlab-org/cloud-native/gitlab-logger.git?tag=v4.0.0&checksum=ec3b9616e4693a2554f23b92f13522eaa6319113"
    gitlab_shell_source       = "https://gitlab.com/gitlab-org/gitlab-shell.git?tag=v14.49.0&checksum=791fd5690e4eef88a7965d96b8f0b5000262d6b6"
  }
}

target "gitlab-base" {
  inherits = ["_gitlab_sources"]
  target   = "gitlab-base"
  tags     = ["10.77.0.9:32443/atum/gitlab-base:v18.11.1-debian13-r1"]
  contexts = { atum_python = "target:debian-runtime" }
  args = {
    ATUM_IMAGE_LICENSES = "MIT AND Ruby AND BSD-2-Clause"
    ATUM_IMAGE_REVISION = "f6fcffcc166d4663e8986364ba84875c7d2215d1+5c7f1724157bdc4ad7a082b430a8dcb4b10b4924+8eba961bb4e69acf85f6c3205196378967c14ef1+c415745b0d50aff8e94c4ccbcbe094897319b8f9+343ea050023cfc0374fdea6fdf625b2f57b716a4+54eaed1d8b56b1aa528be3bdd1877e59c56fa90c"
    ATUM_IMAGE_SOURCE   = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitlab-foss;https://github.com/hairyhenderson/gomplate;https://gitlab.com/gitlab-org/cloud-native/gitlab-logger;https://github.com/ruby/ruby;https://github.com/jemalloc/jemalloc"
    ATUM_IMAGE_TITLE    = "gitlab-base"
    ATUM_IMAGE_VERSION  = "18.11.1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/gitlab-base:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/gitlab-base:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "gitaly" {
  inherits = ["_gitlab_sources"]
  target   = "gitaly"
  tags     = ["10.77.0.9:32443/atum/gitaly:v18.11.1-debian13-r1"]
  contexts = {
    atum_node        = "target:debian-runtime"
    atum_postgresql  = "target:debian-runtime"
    atum_python      = "target:debian-runtime"
    atum_gitlab_base = "target:gitlab-base"
  }
  args = {
    ATUM_IMAGE_LICENSES = "MIT"
    ATUM_IMAGE_REVISION = "f6fcffcc166d4663e8986364ba84875c7d2215d1+f058979acac85cf329f8e4e1c08df2bf99b2da75"
    ATUM_IMAGE_SOURCE   = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitaly"
    ATUM_IMAGE_TITLE    = "gitaly"
    ATUM_IMAGE_VERSION  = "18.11.1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/gitaly:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/gitaly:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "gitlab" {
  name = item.name
  matrix = {
    item = [
      { name = "gitlab-certificates", stage = "gitlab-certificates", version = "18.11.1", tag = "10.77.0.9:32443/atum/gitlab-certificates:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1", source = "https://gitlab.com/gitlab-org/build/CNG" },
      { name = "gitlab-container-registry", stage = "gitlab-container-registry", version = "4.39.0-gitlab", tag = "10.77.0.9:32443/atum/gitlab-container-registry:v4.39.0-gitlab-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+964624812766fc22d167ca56b447e1293767e16c", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/container-registry" },
      { name = "gitlab-toolbox", stage = "gitlab-toolbox", version = "18.11.1", tag = "10.77.0.9:32443/atum/gitlab-toolbox-ce:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+5c7f1724157bdc4ad7a082b430a8dcb4b10b4924", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitlab-foss" },
      { name = "gitlab-webservice", stage = "gitlab-webservice", version = "18.11.1", tag = "10.77.0.9:32443/atum/gitlab-webservice-ce:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+5c7f1724157bdc4ad7a082b430a8dcb4b10b4924", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitlab-foss" },
      { name = "gitlab-workhorse", stage = "gitlab-workhorse", version = "18.11.1", tag = "10.77.0.9:32443/atum/gitlab-workhorse-ce:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+5c7f1724157bdc4ad7a082b430a8dcb4b10b4924", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitlab-foss" },
      { name = "gitlab-sidekiq", stage = "gitlab-sidekiq", version = "18.11.1", tag = "10.77.0.9:32443/atum/gitlab-sidekiq-ce:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+5c7f1724157bdc4ad7a082b430a8dcb4b10b4924", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitlab-foss" },
      { name = "gitlab-shell", stage = "gitlab-shell", version = "14.49.0", tag = "10.77.0.9:32443/atum/gitlab-shell:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+5017b8de0f2d6405da736e6b2c9b602d4474fe72", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitlab-shell" },
      { name = "gitlab-exporter", stage = "gitlab-exporter", version = "16.7.0", tag = "10.77.0.9:32443/atum/gitlab-exporter:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+633101da6e62b1ece051f8762bd89ffaacace6f0", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/gitlab-exporter" },
      { name = "gitlab-kas", stage = "gitlab-kas", version = "18.11.1", tag = "10.77.0.9:32443/atum/gitlab-kas:v18.11.1-debian13-r1", licenses = "MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+4d3884f671ddfa3a197207d992ef65e663a1d31f", source = "https://gitlab.com/gitlab-org/build/CNG;https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent" },
      { name = "cfssl-self-sign", stage = "cfssl-self-sign", version = "1.6.1", tag = "10.77.0.9:32443/atum/cfssl-self-sign:1.6.1-debian13-r1", licenses = "BSD-2-Clause AND MIT", revision = "f6fcffcc166d4663e8986364ba84875c7d2215d1+29ae05fe80e1a9c704ddad7002d90ade7a38cb29", source = "https://gitlab.com/gitlab-org/build/CNG;https://github.com/cloudflare/cfssl" },
    ]
  }
  inherits = ["_gitlab_sources"]
  target   = item.stage
  tags     = [item.tag]
  contexts = {
    atum_gitaly      = item.name == "gitlab-toolbox" ? "target:gitaly" : "target:debian-runtime"
    atum_gitlab_base = "target:gitlab-base"
    atum_go          = item.name == "gitlab-container-registry" || item.name == "gitlab-workhorse" || item.name == "gitlab-shell" || item.name == "gitlab-kas" || item.name == "cfssl-self-sign" ? "target:go-toolchain" : "target:debian-runtime"
    atum_node        = "target:debian-runtime"
    atum_postgresql  = "target:debian-runtime"
    atum_python      = item.name == "gitlab-toolbox" || item.name == "gitlab-webservice" ? "target:python-toolchain" : "target:debian-runtime"
    atum_ruby        = item.name == "gitlab-exporter" ? "target:ruby-toolchain" : "target:debian-runtime"
  }
  args = {
    ATUM_IMAGE_LICENSES = item.licenses
    ATUM_IMAGE_REVISION = item.revision
    ATUM_IMAGE_SOURCE   = item.source
    ATUM_IMAGE_TITLE    = item.name
    ATUM_IMAGE_VERSION  = item.version
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache"]
  cache-to = item.name == "gitlab-exporter" ? [
    "type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache,mode=min,image-manifest=true,oci-mediatypes=true"
    ] : [
    "type=registry,ref=${ATUM_CACHE_REGISTRY}/${item.name}:cache,mode=max,image-manifest=true,oci-mediatypes=true"
  ]
}

target "delivery-build-job" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "delivery-build-job"
  tags       = ["10.77.0.9:32443/atum/build-job:1"]
  contexts = {
    atum_go             = "docker-image://docker.io/library/golang@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b"
    atum_source         = "../.."
    atum_debian_runtime = "docker-image://docker.io/library/debian@sha256:32ccbb2ff8fdcb839bbe9c03c33e4e962b51fe8859249f821638d674b0b88d66"
    atum_docker_cli     = "docker-image://docker.io/library/docker@sha256:cd58b396e427d1ee8cddcc3f3b7e8d8c2ba45755c5dd5b821b6e615e1ccf4586"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/build-job:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/build-job:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "redis-compat" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "redis-compat"
  tags       = ["10.77.0.9:32443/atum/redis:8.4.0-atum1"]
  contexts = {
    atum_redis_upstream = "docker-image://docker.io/library/redis@sha256:0a0f28c99ae50da4e0504499d2cd5b41746135c64f28ec42c88dafad93f60d41"
  }
  args = {
    ATUM_IMAGE_VERSION = "8.4.0-atum1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/redis-compat:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/redis-compat:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "bigbang-harbor-redis-compat" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "redis-compat"
  tags       = ["10.77.0.9:32443/atum/redis:8.8.1-atum1"]
  contexts = {
    atum_redis_upstream = "docker-image://docker.io/library/redis@sha256:4e070415a5713188624f93815e62d6c6a1fcbb416d2e0b578ab3db627db3a93a"
  }
  args = {
    ATUM_IMAGE_VERSION = "8.8.1-atum1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/bigbang-harbor-redis-compat:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/bigbang-harbor-redis-compat:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "redis-exporter-compat" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "redis-exporter-compat"
  tags       = ["10.77.0.9:32443/atum/redis-exporter:v1.86.0"]
  contexts = {
    atum_debian_runtime          = "docker-image://docker.io/library/debian@sha256:32ccbb2ff8fdcb839bbe9c03c33e4e962b51fe8859249f821638d674b0b88d66"
    atum_redis_exporter_upstream = "docker-image://docker.io/oliver006/redis_exporter:v1.86.0@sha256:9e19fc77b9c5cb138a9ec9335b8bbcbbed620c4df54f7eb29329cdd8db148f1d"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/redis-exporter-compat:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/redis-exporter-compat:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "postgresql-17-compat" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "postgresql-compat"
  tags       = ["10.77.0.9:32443/atum/postgresql:17.4"]
  contexts = {
    atum_postgresql_upstream = "docker-image://docker.io/library/postgres@sha256:d4eceb7552a57997fff2e9ceb1a624210e61b6432a2a1f7934a418c27bfe1406"
  }
  args = {
    ATUM_IMAGE_VERSION = "17.4"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/postgresql-17-compat:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/postgresql-17-compat:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "postgresql-18-compat" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "postgresql-compat"
  tags       = ["10.77.0.9:32443/atum/postgresql:18.4"]
  contexts = {
    atum_postgresql_upstream = "docker-image://docker.io/library/postgres@sha256:4cc13dede823cab4e05290c7fb3350fb4e599ecabd9b07e6706b5d5e8f5bc929"
  }
  args = {
    ATUM_IMAGE_VERSION = "18.4"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/postgresql-18-compat:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/postgresql-18-compat:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "grafana-plugins" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "grafana-plugins"
  tags       = ["10.77.0.9:32443/atum/grafana-plugins:13.0.1-atum1"]
  contexts = {
    atum_grafana_upstream = "docker-image://docker.io/grafana/grafana@sha256:3625fdfa3cab904abdf9faaff8f40de0639b456ac5c5d322964fe705051d5455"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/grafana-plugins:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/grafana-plugins:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}
