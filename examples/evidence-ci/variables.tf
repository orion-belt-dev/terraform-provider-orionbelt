variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name" {
  type    = string
  default = "orionbelt"
}

variable "evidence_bucket" {
  description = "Name of the S3 Object Lock evidence bucket."
  type        = string
}

variable "evidence_kms_key_arn" {
  description = "KMS key that encrypts the evidence bucket."
  type        = string
}

variable "github_repository" {
  description = "Repository allowed to assume the role, as owner/repo."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "Use owner/repo."
  }
}

variable "github_environment" {
  description = "GitHub environment the evidence job runs in. Restrict its deployment branches to the protected branch."
  type        = string
  default     = "evidence"
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC provider. Set false if the account already has one."
  type        = bool
  default     = true
}
