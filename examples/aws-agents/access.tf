resource "orionbelt_user" "engineer_1" {
  username = "eng-01"
  email    = "eng-01@example.com"
  role     = "user"
}

resource "orionbelt_user" "engineer_2" {
  username = "eng-02"
  email    = "eng-02@example.com"
  role     = "user"
}

resource "orionbelt_machine_access" "target" {
  for_each = var.agents

  machine_id = orionbelt_agent.this[each.key].id

  grant {
    user_id      = orionbelt_user.engineer_1.id
    access_type  = "ssh"
    remote_users = ["deploy"]
    expires_at   = var.access_review_date
  }

  grant {
    user_id      = orionbelt_user.engineer_2.id
    access_type  = "ssh"
    remote_users = ["deploy"]
    expires_at   = var.access_review_date
  }
}

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

data "orionbelt_access_review" "all" {
  depends_on = [orionbelt_machine_access.target]
}

data "orionbelt_compliance_profile" "this" {}

check "access_review" {
  assert {
    condition     = data.orionbelt_access_review.all.compliant
    error_message = "Access review has findings: ${jsonencode(data.orionbelt_access_review.all.findings)}"
  }
}
