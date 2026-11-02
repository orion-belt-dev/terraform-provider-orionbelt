data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_iam_policy_document" "gateway_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "gateway" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.jwt_secret.arn,
      aws_secretsmanager_secret.recording_key.arn,
      aws_db_instance.this.master_user_secret[0].secret_arn,
    ]
  }

  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.this.arn]
  }

  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/recordings/*"]
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }
}

resource "aws_iam_role" "gateway" {
  name               = "${var.name}-gateway"
  assume_role_policy = data.aws_iam_policy_document.gateway_assume.json
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway.json
}

resource "aws_iam_role_policy_attachment" "gateway_ssm" {
  role       = aws_iam_role.gateway.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "gateway" {
  name = "${var.name}-gateway"
  role = aws_iam_role.gateway.name
}

resource "aws_instance" "gateway" {
  ami                         = data.aws_ssm_parameter.ubuntu.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[0].id
  vpc_security_group_ids      = [aws_security_group.gateway.id]
  iam_instance_profile        = aws_iam_instance_profile.gateway.name
  associate_public_ip_address = false
  ebs_optimized               = true
  monitoring                  = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
    kms_key_id  = aws_kms_key.this.arn
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region                = data.aws_region.current.region
    public_url            = "https://${var.gateway_fqdn}"
    fqdn                  = var.gateway_fqdn
    db_host               = aws_db_instance.this.address
    db_secret_arn         = aws_db_instance.this.master_user_secret[0].secret_arn
    jwt_secret_arn        = aws_secretsmanager_secret.jwt_secret.arn
    recording_secret_arn  = aws_secretsmanager_secret.recording_key.arn
    evidence_bucket       = aws_s3_bucket.evidence.id
    kms_key_arn           = aws_kms_key.this.arn
    recording_retention_d = var.evidence_retention_days
  })
  user_data_replace_on_change = true

  tags = { Name = "${var.name}-gateway" }

  depends_on = [
    aws_secretsmanager_secret_version.jwt_secret,
    aws_secretsmanager_secret_version.recording_key,
    aws_iam_role_policy.gateway,
  ]
}
