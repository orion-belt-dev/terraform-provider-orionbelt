variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "gateway_url" {
  description = "Gateway API URL. The API key comes from ORIONBELT_API_KEY."
  type        = string
}

variable "gateway_ssh_cidrs" {
  description = "Addresses of the gateway's SSH listener the agents may dial."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  description = "Private subnet for the targets."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t3.small"
}

variable "agents" {
  description = "Target hosts, keyed by agent name."
  type        = map(object({ env = string }))
}

variable "agent_key_version" {
  description = "Bump to rotate every agent's keypair. The agents are re-registered."
  type        = number
  default     = 1
}

variable "access_review_date" {
  description = "RFC 3339 expiry for every grant. Must fall within the framework's maximum grant duration."
  type        = string

  validation {
    condition     = can(timecmp(var.access_review_date, "2000-01-01T00:00:00Z"))
    error_message = "Use an RFC 3339 timestamp such as 2027-01-31T00:00:00Z."
  }
}
