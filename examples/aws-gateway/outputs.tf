output "gateway_url" {
  value = "https://${var.gateway_fqdn}"
}

output "ssh_endpoint" {
  value = "${var.gateway_fqdn}:2222"
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "evidence_kms_key_arn" {
  value = aws_kms_key.this.arn
}
