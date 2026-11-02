# aws-agents

- Registers agents and launches private targets with no inbound rules, IMDSv2, encrypted volumes, and a role limited to its own key secret.
- Two engineers, expiring grants, PCI-compliant risk policy, and a `check` on the access review. Evidence is exported as JSON outputs.
- Plans fail with control citations if anything violates SOC 2 or PCI DSS 4.0.

Key handling: an ephemeral ED25519 key is written to two write-only arguments, the private half to a Secrets Manager secret and the public half to an SSM parameter. A regular data source reads the public half back for `orionbelt_agent.public_key`. Ephemeral values cannot flow into ordinary attributes, so the SSM round trip is the only way to keep the private key out of state and plans. The public key is not secret, so it appears in state. Rotate by bumping `agent_key_version`, which replaces the agents.

Grant expiry is a variable rather than `timeadd(plantimestamp(), ...)` because `plantimestamp()` changes every plan and would show a perpetual diff. Bump `access_review_date` in a PR at each access review; the provider rejects dates beyond the framework maximum (30 days for PCI).

```sh
export ORIONBELT_API_KEY=...
terraform init
terraform apply \
  -var gateway_url=https://orion.example.com \
  -var vpc_id=vpc-123 -var subnet_id=subnet-123 \
  -var 'agents={ web-1 = { env = "prod" } }' \
  -var access_review_date=2026-11-30T00:00:00Z
terraform output -raw access_review > access-review.json
```
