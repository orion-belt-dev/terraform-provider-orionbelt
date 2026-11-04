# The private key stays on the host: private_key_command fetches it at boot.
resource "orionbelt_agent" "web" {
  name                = "web-1"
  public_key          = var.agent_public_key
  private_key_command = "aws secretsmanager get-secret-value --secret-id agents/web-1 --query SecretString --output text"
}

# cloud_init can be passed straight to an instance's user_data.
output "web_user_data" {
  value     = orionbelt_agent.web.cloud_init
  sensitive = true
}
