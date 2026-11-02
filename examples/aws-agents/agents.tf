data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

ephemeral "tls_private_key" "agent" {
  for_each = var.agents

  algorithm = "ED25519"
}

resource "aws_kms_key" "agent" {
  for_each = var.agents

  description             = "Agent key for ${each.key}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_secretsmanager_secret" "agent_key" {
  for_each = var.agents

  name       = "orionbelt/agents/${each.key}/key"
  kms_key_id = aws_kms_key.agent[each.key].arn
}

resource "aws_secretsmanager_secret_version" "agent_key" {
  for_each = var.agents

  secret_id                = aws_secretsmanager_secret.agent_key[each.key].id
  secret_string_wo         = ephemeral.tls_private_key.agent[each.key].private_key_openssh
  secret_string_wo_version = var.agent_key_version
}

resource "aws_ssm_parameter" "agent_public_key" {
  for_each = var.agents

  name             = "/orionbelt/agents/${each.key}/public-key"
  type             = "String"
  value_wo         = ephemeral.tls_private_key.agent[each.key].public_key_openssh
  value_wo_version = var.agent_key_version
}

data "aws_ssm_parameter" "agent_public_key" {
  for_each = var.agents

  name = aws_ssm_parameter.agent_public_key[each.key].name

  depends_on = [aws_ssm_parameter.agent_public_key]
}

resource "orionbelt_agent" "this" {
  for_each = var.agents

  name       = each.key
  public_key = data.aws_ssm_parameter.agent_public_key[each.key].insecure_value
  tags       = { env = each.value.env }

  private_key_command = join(" ", [
    "aws secretsmanager get-secret-value",
    "--region ${var.region}",
    "--secret-id ${aws_secretsmanager_secret.agent_key[each.key].arn}",
    "--query SecretString --output text",
  ])
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "agent" {
  for_each = var.agents

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.agent_key[each.key].arn]
  }

  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.agent[each.key].arn]
  }
}

resource "aws_iam_role" "agent" {
  for_each = var.agents

  name               = "orionbelt-agent-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "agent" {
  for_each = var.agents

  name   = "agent-key"
  role   = aws_iam_role.agent[each.key].id
  policy = data.aws_iam_policy_document.agent[each.key].json
}

resource "aws_iam_role_policy_attachment" "agent_ssm" {
  for_each = var.agents

  role       = aws_iam_role.agent[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "agent" {
  for_each = var.agents

  name = "orionbelt-agent-${each.key}"
  role = aws_iam_role.agent[each.key].name
}

resource "aws_security_group" "agent" {
  name        = "orionbelt-agents"
  description = "Agent targets: no inbound, egress to gateway SSH and HTTPS"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "gateway_ssh" {
  for_each = toset(var.gateway_ssh_cidrs)

  security_group_id = aws_security_group.agent.id
  description       = "Reverse SSH to gateway"
  ip_protocol       = "tcp"
  from_port         = 2222
  to_port           = 2222
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.agent.id
  description       = "Package install and AWS APIs"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "target" {
  for_each = var.agents

  ami                         = data.aws_ssm_parameter.al2023.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.agent.id]
  iam_instance_profile        = aws_iam_instance_profile.agent[each.key].name
  associate_public_ip_address = false
  ebs_optimized               = true
  monitoring                  = true
  user_data                   = orionbelt_agent.this[each.key].cloud_init
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    encrypted   = true
    kms_key_id  = aws_kms_key.agent[each.key].arn
  }

  tags = { Name = each.key }
}
