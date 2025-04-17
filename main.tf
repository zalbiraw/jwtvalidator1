terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0.0"
    }
  }
}

variable "namespace" {
  description = "The namespace for the config map"
  type        = string
}

resource "kubernetes_config_map" "jwt_validator" {
  metadata {
    name      = "jwt-validator-plugin"
    namespace = var.namespace
  }

  data = merge({
    ".golangci.yml" = file("${path.module}/.golangci.yml")
    ".traefik.yml" = file("${path.module}/.traefik.yml")
    "go.mod" = file("${path.module}/go.mod")
    "jwtvalidator.go" = file("${path.module}/jwtvalidator.go")
    "Makefile" = file("${path.module}/Makefile")
    "jwtvalidator_test.go" = file("${path.module}/jwtvalidator_test.go")
  })
}
