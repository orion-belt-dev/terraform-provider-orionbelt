# evidence-ci

Ships signed compliance evidence from GitHub Actions into the Object Lock evidence bucket of `aws-gateway`.

- `main.tf` creates an IAM role for GitHub OIDC. Trust is exact: audience `sts.amazonaws.com`, subject `repo:<repo>:environment:<environment>`. It can only `s3:PutObject` under `evidence/*` and `kms:GenerateDataKey` via S3. No get, list, delete, retention or bypass.
- `evidence.yml` plans your infra, builds a redacted report with `orionbelt-evidence`, attests it, uploads report and attestation bundle to `evidence/YYYY/MM/DD/<run>-<attempt>/`, then fails the job if `compliant` is false (after upload, so failing evidence is kept).

## Setup

1. Apply this module with the gateway outputs: `evidence_bucket` and `evidence_kms_key_arn`, plus `github_repository`. Set `create_oidc_provider = false` if the account already has the GitHub provider.
2. In the infra repo create the environment `evidence` and restrict its deployment branches to the protected branch. In it set variables `ORIONBELT_URL`, `ORIONBELT_EVIDENCE_VERSION` (a release tag), `EVIDENCE_BUCKET`, `AWS_REGION`, `TERRAFORM_PLAN_ROLE_ARN` (its own state/read role), `EVIDENCE_ROLE_ARN` (`evidence_role_arn` output), and secret `ORIONBELT_API_KEY`.
3. Copy `evidence.yml` to `.github/workflows/` in the infra repo.

## Verify a stored record

    aws s3 cp s3://$BUCKET/evidence/2026/11/02/<run>-1/evidence.json .
    aws s3 cp s3://$BUCKET/evidence/2026/11/02/<run>-1/evidence.sigstore.json .
    gh attestation verify evidence.json --repo owner/repo --bundle evidence.sigstore.json \
      --signer-workflow owner/repo/.github/workflows/evidence.yml
    aws s3api get-object-retention --bucket $BUCKET --key evidence/2026/11/02/<run>-1/evidence.json

## Caveats

- Attestations on private repositories need GitHub Enterprise Cloud.
- The plan JSON is hashed into the evidence but never stored or uploaded; the workflow deletes it right after the report is built.
- The infra config must include `data "orionbelt_compliance_profile"` (else the CLI fails) and `data "orionbelt_access_review"` (else the report is not compliant). A review with `depends_on` is deferred to apply while its dependencies have pending changes, and a deferred review is not compliant.
- `compliant` is false when a review has findings, a review is missing or deferred, or an `orionbelt_*` resource drifted. Other drift is listed but does not fail it. `reasons` says which.
- The role trusts any job in the `evidence` environment; the branch restriction is what keeps it to reviewed code, and `--signer-workflow` pins verification to this workflow.
- The API key is only in the plan step's environment, and `orionbelt-evidence` is installed from a release tag before any credentials are set and runs with an empty environment.
- A plan that fails (including a compliance guardrail at plan time) writes no report; the failed run is the record. Guardrails are meant to stop violations in pull requests, before they reach the protected branch.
- Uploads are single-part; above 8 MB `aws s3 cp` switches to multipart, which would also need `kms:Decrypt`.
