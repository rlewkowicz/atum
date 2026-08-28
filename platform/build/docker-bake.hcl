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
  default = "10.77.0.9:32443/atum/sbom-scanner:1.11.0-mirror-13864237fb990943433f89d698590aad1de38d4a7e13d38e"
}

variable "SOURCE_DATE_EPOCH" {
  default = "0"
}

group "default" {
  targets = ["atum-operator", "garage-init-helper", "grafana-plugins", "postgresql-18-compat", "vault-curl-compat"]
}

target "_common" {
  context   = "."
  platforms = [ATUM_PLATFORM]
  args = {
    ATUM_DEBIAN_IMAGE = ATUM_DEBIAN_IMAGE
    ATUM_IMAGE_CREATED = "1970-01-01T00:00:00Z"
    SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
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

target "atum-operator" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.operator"
  target     = "atum-operator"
  tags       = ["10.77.0.9:32443/atum/atum-operator:build-82271ae3912524e04ace0c19c94393b96266e1f3b7fd601c658725f8a420a581"]
  contexts = {
    atum_go_upstream = "docker-image://docker.io/library/golang:1.26.0-alpine@sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135"
    atum_source = "../.."
  }
  args = {
    ATUM_IMAGE_LICENSE = "Apache-2.0"
    ATUM_IMAGE_SOURCE = "https://github.com/rlewkowicz/atum"
    ATUM_IMAGE_VERSION = "0.1.1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/atum-operator:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/atum-operator:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "garage-init-helper" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "garage-init-helper"
  tags       = ["10.77.0.9:32443/atum/garage-init-helper:build-6e11fdb722599abd4ee2658ec956bbf9e623cfe3290eb5a54bf69b27efde9ac1"]
  args = {
    ATUM_IMAGE_LICENSE = "Debian"
    ATUM_IMAGE_SOURCE = "https://www.debian.org/;https://snapshot.debian.org/"
    ATUM_IMAGE_VERSION = "2.1.0"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/garage-init-helper:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/garage-init-helper:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "grafana-plugins" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "grafana-plugins"
  tags       = ["10.77.0.9:32443/atum/grafana-plugins:build-7cf9b3e38281fbdee82791ef19f54dd70af729cbeac6eb8133dca60ea7837eee"]
  contexts = {
    atum_grafana_upstream = "docker-image://docker.io/grafana/grafana@sha256:3625fdfa3cab904abdf9faaff8f40de0639b456ac5c5d322964fe705051d5455"
  }
  args = {
    ATUM_IMAGE_LICENSE = "AGPL-3.0-only AND Apache-2.0"
    ATUM_IMAGE_REVISION = "c19f9aa194bc684d12eb69660e0d38dc43f4b55d09c24d524a95b1b665e4088a"
    ATUM_IMAGE_SOURCE = "https://github.com/grafana/grafana;https://github.com/grafana/piechart-panel;https://github.com/grafana/grafana-polystat-panel;https://github.com/RedisGrafana/grafana-redis-datasource"
    ATUM_IMAGE_VERSION = "13.0.1"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/grafana-plugins:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/grafana-plugins:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "postgresql-18-compat" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "postgresql-compat"
  tags       = ["10.77.0.9:32443/atum/postgresql-18:build-f2e99d3562fafd5b2f658a99550db5f856c982ba856dd0070f1ea786f626bcc9"]
  contexts = {
    atum_postgresql_upstream = "docker-image://docker.io/library/postgres@sha256:4cc13dede823cab4e05290c7fb3350fb4e599ecabd9b07e6706b5d5e8f5bc929"
  }
  args = {
    ATUM_IMAGE_LICENSE = "PostgreSQL AND Apache-2.0"
    ATUM_IMAGE_SOURCE = "https://github.com/docker-library/postgres;https://github.com/bitnami/charts;https://github.com/rlewkowicz/atum"
    ATUM_IMAGE_VERSION = "18.4"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/postgresql-18-compat:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/postgresql-18-compat:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}

target "vault-curl-compat" {
  inherits   = ["_attested"]
  dockerfile = "docker/Dockerfile.delivery"
  target     = "vault-curl-compat"
  tags       = ["10.77.0.9:32443/atum/vault:build-4bab8e37b10c2d1531d8e7bfb311927623660fd7664185fd3a8563957527b1d5"]
  contexts = {
    atum_curl_upstream = "docker-image://docker.io/curlimages/curl@sha256:43ebaa53d3806db6b1ce4353b6b26ae638ec1c167ee351524b05690f988bb20d"
    atum_vault_upstream = "docker-image://docker.io/hashicorp/vault@sha256:6c77f568e6b6310d5bc68befb5711b9215c574de7da489e7c24332581176888b"
  }
  args = {
    ATUM_IMAGE_LICENSE = "BUSL-1.1 AND curl"
    ATUM_IMAGE_SOURCE = "docker.io/hashicorp/vault;https://curl.se/;https://github.com/rlewkowicz/atum"
    ATUM_IMAGE_VERSION = "1.21.4"
  }
  cache-from = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/vault-curl-compat:cache"]
  cache-to   = ["type=registry,ref=${ATUM_CACHE_REGISTRY}/vault-curl-compat:cache,mode=max,image-manifest=true,oci-mediatypes=true"]
}
