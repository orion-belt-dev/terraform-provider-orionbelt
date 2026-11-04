data "orionbelt_access_review" "all" {}

check "access_review" {
  assert {
    condition     = data.orionbelt_access_review.all.compliant
    error_message = "Access review has findings: ${jsonencode(data.orionbelt_access_review.all.findings)}"
  }
}
