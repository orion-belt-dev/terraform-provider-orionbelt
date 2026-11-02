resource "aws_security_group" "nlb" {
  name        = "${var.name}-nlb"
  description = "Internet-facing load balancer"
  vpc_id      = aws_vpc.this.id
}

resource "aws_security_group" "gateway" {
  name        = "${var.name}-gateway"
  description = "Gateway instance"
  vpc_id      = aws_vpc.this.id
}

resource "aws_security_group" "db" {
  name        = "${var.name}-db"
  description = "PostgreSQL"
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_ingress_rule" "nlb_api" {
  for_each = toset(var.api_allowed_cidrs)

  security_group_id = aws_security_group.nlb.id
  description       = "HTTPS API and console"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "nlb_ssh" {
  for_each = toset(var.agent_egress_cidrs)

  security_group_id = aws_security_group.nlb.id
  description       = "Agent reverse SSH"
  ip_protocol       = "tcp"
  from_port         = 2222
  to_port           = 2222
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "nlb_api" {
  security_group_id            = aws_security_group.nlb.id
  description                  = "To gateway API"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.gateway.id
}

resource "aws_vpc_security_group_egress_rule" "nlb_ssh" {
  security_group_id            = aws_security_group.nlb.id
  description                  = "To gateway SSH"
  ip_protocol                  = "tcp"
  from_port                    = 2222
  to_port                      = 2222
  referenced_security_group_id = aws_security_group.gateway.id
}

resource "aws_vpc_security_group_ingress_rule" "gateway_api" {
  security_group_id            = aws_security_group.gateway.id
  description                  = "API from load balancer"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.nlb.id
}

resource "aws_vpc_security_group_ingress_rule" "gateway_ssh" {
  security_group_id            = aws_security_group.gateway.id
  description                  = "Agent SSH from load balancer"
  ip_protocol                  = "tcp"
  from_port                    = 2222
  to_port                      = 2222
  referenced_security_group_id = aws_security_group.nlb.id
}

resource "aws_vpc_security_group_egress_rule" "gateway_https" {
  security_group_id = aws_security_group.gateway.id
  description       = "Package repository, AWS APIs, SSM"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "gateway_db" {
  security_group_id            = aws_security_group.gateway.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.db.id
}

resource "aws_vpc_security_group_ingress_rule" "db_gateway" {
  security_group_id            = aws_security_group.db.id
  description                  = "From gateway"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.gateway.id
}
