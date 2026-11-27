# Security exceptions

Scanner findings we accept, and why. Each one is also listed in
`.trivyignore.yaml` with the same expiry, so Trivy reports it again after
the review date.

| Advisory | Where | Why it is acceptable | Owner | Review by |
| --- | --- | --- | --- | --- |
| AVD-AWS-0104 (egress to 0.0.0.0/0) | `examples/aws-gateway/security.tf`, `aws_vpc_security_group_egress_rule.gateway_https` | TCP 443 only, for the package repository, AWS APIs and SSM. The example does not create VPC endpoints or an egress proxy, so those services have no fixed address range. Deployments with endpoints or a proxy should narrow it. | mdarguechi | 2027-02-25 |
| AVD-AWS-0104 (egress to 0.0.0.0/0) | `examples/aws-agents/agents.tf`, `aws_vpc_security_group_egress_rule.https` and the default of `gateway_ssh_cidrs` | Agents have no inbound rules and dial out. HTTPS is needed for package installs and AWS APIs for the same reason as above. `gateway_ssh_cidrs` defaults to any address because the example does not know the gateway's address; its description says to set it. | mdarguechi | 2027-02-25 |
| AVD-AWS-0053 (public load balancer) | `examples/aws-gateway/nlb.tf`, `aws_lb.this` | The NLB is how users and agents reach the gateway. Ingress is limited by `api_allowed_cidrs` and `agent_egress_cidrs`, and both reject `0.0.0.0/0`. The instances stay in private subnets. | mdarguechi | 2027-02-25 |
