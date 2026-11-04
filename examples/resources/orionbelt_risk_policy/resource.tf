# The gateway has a single risk policy.
resource "orionbelt_risk_policy" "this" {
  auto_approve {
    max_sensitivity      = "low"
    max_duration_seconds = 3600
    require_mfa          = true
    remote_users         = ["deploy"]
  }

  escalate {
    without_mfa = true
  }
}
