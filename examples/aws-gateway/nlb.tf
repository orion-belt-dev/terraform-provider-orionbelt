resource "aws_lb" "this" {
  name                             = var.name
  load_balancer_type               = "network"
  internal                         = false
  subnets                          = aws_subnet.public[*].id
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = true
}

resource "aws_lb_target_group" "api" {
  name               = "${var.name}-api"
  vpc_id             = aws_vpc.this.id
  target_type        = "ip"
  protocol           = "TCP"
  port               = 8080
  preserve_client_ip = "false"

  health_check {
    protocol = "TCP"
  }
}

resource "aws_lb_target_group" "ssh" {
  name               = "${var.name}-ssh"
  vpc_id             = aws_vpc.this.id
  target_type        = "ip"
  protocol           = "TCP"
  port               = 2222
  preserve_client_ip = "false"

  health_check {
    protocol = "TCP"
  }
}

resource "aws_lb_target_group_attachment" "api" {
  target_group_arn = aws_lb_target_group.api.arn
  target_id        = aws_instance.gateway.private_ip
}

resource "aws_lb_target_group_attachment" "ssh" {
  target_group_arn = aws_lb_target_group.ssh.arn
  target_id        = aws_instance.gateway.private_ip
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.this.arn
  protocol          = "TLS"
  port              = 443
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "ssh" {
  load_balancer_arn = aws_lb.this.arn
  protocol          = "TCP"
  port              = 2222

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ssh.arn
  }
}

resource "aws_route53_record" "gateway" {
  zone_id = var.route53_zone_id
  name    = var.gateway_fqdn
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}
