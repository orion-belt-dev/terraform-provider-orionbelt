# aws-gateway

- Private VPC; only the NLB is public (TLS 443 for the API, TCP 2222 for agents). No inbound 22.
- Gateway on EC2: IMDSv2 only, CMK-encrypted gp3, no public IP or key pair, SSM for break-glass.
- JWT secret and recording key generated as `ephemeral` values and written to Secrets Manager with write-only arguments; the DB password is the RDS-managed secret. None reach state or user_data.
- RDS PostgreSQL 16: private, CMK-encrypted, `rds.force_ssl`, deletion protection, Performance Insights encrypted.
- S3 evidence bucket: Object Lock (compliance), versioning, SSE-KMS, TLS-only. Recordings sync there every 5 minutes.
- VPC flow logs to a KMS-encrypted log group.

```sh
terraform init
terraform apply \
  -var gateway_fqdn=orion.example.com \
  -var route53_zone_id=Z123 \
  -var acm_certificate_arn=arn:aws:acm:... \
  -var 'api_allowed_cidrs=["203.0.113.0/24"]' \
  -var 'agent_egress_cidrs=["198.51.100.10/32"]'

# create the first admin (no network-exposed bootstrap)
aws ssm start-session --target <gateway-instance-id>
sudo -u orionbelt orion-belt-server -c /etc/orion-belt/server.yaml setup
```
