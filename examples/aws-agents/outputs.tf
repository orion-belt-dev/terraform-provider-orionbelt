output "compliance_profile" {
  value = jsonencode(data.orionbelt_compliance_profile.this)
}

output "access_review" {
  value = jsonencode(data.orionbelt_access_review.all)
}
