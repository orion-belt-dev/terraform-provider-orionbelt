# terraform-provider-orionbelt

Terraform and OpenTofu provider for the [Orion Belt](https://github.com/orion-belt-dev/orion-belt) access gateway. Users, grants, agents and risk policy as code, with SOC 2, ISO 27001 and PCI DSS 4.0 rules enforced by the provider.

- Rules are checked at plan and again at apply. Errors cite the control.
- `orionbelt_machine_access` revokes grants made outside Terraform.
- Grants expire at an absolute time and are never renewed implicitly.
- `orionbelt_access_review` checks live access against the same rules.
- Agent private keys never pass through Terraform.
- `orionbelt-evidence` turns each plan into a signed evidence report.

## Example

```hcl
terraform {
  required_providers {
    orionbelt = { source = "orion-belt-dev/orionbelt" }
  }
}

provider "orionbelt" {
  url = "https://orion.example.com" # or ORIONBELT_URL; API key from ORIONBELT_API_KEY

  compliance {
    frameworks = ["soc2", "pci-dss-4"]
  }
}

resource "orionbelt_user" "engineer" {
  username = "eng-01"
  email    = "eng-01@example.com"
}

resource "orionbelt_agent" "web" {
  name                = "web-1"
  public_key          = var.agent_public_key
  private_key_command = "aws secretsmanager get-secret-value --secret-id agents/web-1 --query SecretString --output text"
}

resource "orionbelt_machine_access" "web" {
  machine_id = orionbelt_agent.web.id

  grant {
    user_id      = orionbelt_user.engineer.id
    access_type  = "ssh"
    remote_users = ["deploy"]
    expires_at   = "2027-01-31T00:00:00Z"
  }
}
```

`orionbelt_agent.web.cloud_init` can be passed straight to EC2 `user_data`.

## Provider

| Argument | Description |
| --- | --- |
| `url` | Gateway URL. HTTPS required. Env `ORIONBELT_URL`. |
| `api_key` | Admin or operator API key. Env `ORIONBELT_API_KEY`. |
| `ca_cert_pem` | CA bundle for the gateway's TLS certificate. Replaces system roots. |
| `insecure_http` | Allow `http://`. Local labs only. |
| `timeout` | Per-request timeout. Default `30s`. |
| `compliance.frameworks` | `soc2`, `iso27001`, `pci-dss-4`. The strictest setting wins. |
| `compliance.max_grant_duration` | Tighter grant limit, e.g. `720h`. |
| `compliance.denied_remote_users` | Remote accounts no grant may name. |

## Resources and data sources

| Name | Purpose |
| --- | --- |
| `orionbelt_user` | User account. |
| `orionbelt_permission` | One standing grant. |
| `orionbelt_machine_access` | All grants on one machine. Unknown grants are revoked. |
| `orionbelt_agent` | Registers an agent by public key; renders `agent_yaml` and `cloud_init`. Archived on destroy. |
| `orionbelt_risk_policy` | Access request auto-approval and escalation. |
| `data.orionbelt_gateway` | Gateway info and SSH CA keys. |
| `data.orionbelt_machine`, `data.orionbelt_user` | Lookups by name. |
| `data.orionbelt_access_review` | Effective access and compliance findings. |
| `data.orionbelt_compliance_profile` | Rules in force and their controls. |

## Compliance

| Rule | SOC 2 | ISO 27001 | PCI DSS 4.0 |
| --- | --- | --- | --- |
| Grants expire | ≤ 90 days | ≤ 90 days | ≤ 30 days |
| No `root` grants | | | ✓ |
| No shared accounts, email required | ✓ | ✓ | ✓ |
| Agents archived, never deleted | ✓ | ✓ | ✓ |
| Gateway host key verified (CA or pinned) | | ✓ | ✓ |
| MFA before escalation, auto-approval ≤ 8h | | | ✓ |

```text
Error: Compliance violation: denied-remote-user

remote user "root" is not allowed; grant a named, least-privileged account
(PCI DSS 4.0 7.2.2, PCI DSS 4.0 8.6.1)
```

## Security

- Agents register with a public key. `private_key_command` fetches the private key on the host at boot; cloud-init stops if it fails.
- Agents verify the gateway by SSH CA or pinned host key.
- HTTPS only, TLS 1.2+, no redirects, no credentials in the URL.
- `agent.yaml` and cloud-init are marshalled from structs, not templated.
- Releases are GPG-signed with an SBOM and build provenance. Actions are pinned by SHA. CI runs CodeQL, govulncheck and Scorecard.

## Evidence

`cmd/orionbelt-evidence` reads `terraform show -json` and writes a report with the frameworks in force, control status, access review findings, drift, and the plan's SHA-256. Attribute values are not copied. `examples/evidence-ci` runs it in GitHub Actions, attests it, and stores it in S3 Object Lock.

## Examples

| Directory | Contents |
| --- | --- |
| `examples/aws-gateway` | Gateway on AWS: private EC2 behind a TLS NLB, RDS, KMS, flow logs, Object Lock bucket. |
| `examples/aws-agents` | Agents with no inbound ports, keys in Secrets Manager kept out of state, key rotation. |
| `examples/compliance-violation` | A config that breaks PCI DSS 4.0, and the errors. |
| `examples/evidence-ci` | OIDC role and workflow for signed evidence. |

## Development

```sh
make build
make test      # real terraform binary against an in-memory gateway
make lint
TF_ACC=1 ORIONBELT_URL=... ORIONBELT_API_KEY=... make testacc
```

Go 1.27, Terraform 1.11+ or OpenTofu.

## License

Apache License 2.0 with the Commons Clause, as Orion Belt. See [LICENSE](LICENSE).
