ephemeral "random_password" "jwt_secret" {
  length  = 64
  special = false
}

ephemeral "random_password" "recording_key" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name       = "${var.name}/jwt-secret"
  kms_key_id = aws_kms_key.this.arn
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id                = aws_secretsmanager_secret.jwt_secret.id
  secret_string_wo         = ephemeral.random_password.jwt_secret.result
  secret_string_wo_version = var.secrets_version
}

resource "aws_secretsmanager_secret" "recording_key" {
  name       = "${var.name}/recording-key"
  kms_key_id = aws_kms_key.this.arn
}

resource "aws_secretsmanager_secret_version" "recording_key" {
  secret_id                = aws_secretsmanager_secret.recording_key.id
  secret_string_wo         = ephemeral.random_password.recording_key.result
  secret_string_wo_version = var.secrets_version
}
