variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name" {
  type    = string
  default = "orionbelt"
}

variable "gateway_fqdn" {
  description = "Public hostname of the gateway, covered by the ACM certificate."
  type        = string
}

variable "route53_zone_id" {
  type = string
}

variable "acm_certificate_arn" {
  type = string
}

variable "api_allowed_cidrs" {
  description = "Networks allowed to reach the HTTPS API and console."
  type        = list(string)

  validation {
    condition     = !contains(var.api_allowed_cidrs, "0.0.0.0/0")
    error_message = "Restrict API access to known networks."
  }
}

variable "agent_egress_cidrs" {
  description = "Public egress addresses (e.g. NAT gateway EIPs) of the networks agents dial from."
  type        = list(string)

  validation {
    condition     = !contains(var.agent_egress_cidrs, "0.0.0.0/0")
    error_message = "List the agents' egress addresses explicitly."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "root_volume_gb" {
  type    = number
  default = 50
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_allocated_storage_gb" {
  type    = number
  default = 50
}

variable "db_backup_retention_days" {
  type    = number
  default = 14
}

variable "evidence_retention_days" {
  description = "Object Lock compliance-mode retention. Locked objects cannot be deleted by anyone until it elapses."
  type        = number
  default     = 365
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "secrets_version" {
  description = "Bump to regenerate the JWT secret and recording key."
  type        = number
  default     = 1
}
