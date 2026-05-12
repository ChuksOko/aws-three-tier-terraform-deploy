# =============================================================================
# Cloudflare Zero Trust - Infrastructure as Code
# =============================================================================
# Manages Cloudflare Access policies for the banking API Zero Trust protection.
# All previously manual dashboard configurations are now version-controlled.
#
# Provider: cloudflare/cloudflare v4.52.7
# Author:   Chukwuemeka Oko
# Project:  aws-three-tier-terraform-deploy - Zero Trust Identity Pivot v2
# =============================================================================

# -----------------------------------------------------------------------------
# Cloudflare Access Application
# Imported from existing dashboard configuration
# ID: c7a198de-af85-4fe3-adfd-393bb676400c
# -----------------------------------------------------------------------------
resource "cloudflare_zero_trust_access_application" "banking_api" {
  account_id       = var.cloudflare_account_id
  name             = "skybound02.online"
  domain           = var.banking_api_domain
  type             = "self_hosted"
  session_duration = "24h"

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [allowed_idps, tags]
  }
}

# -----------------------------------------------------------------------------
# Cloudflare Access Policy - Google OIDC Authentication
# Imported from existing dashboard configuration
# ID: f7210e80-9328-4dd8-87c6-e02883d7758a
# -----------------------------------------------------------------------------
resource "cloudflare_zero_trust_access_policy" "google_oidc" {
  account_id     = var.cloudflare_account_id
  application_id = cloudflare_zero_trust_access_application.banking_api.id
  name           = "Google OIDC + Device Check"
  precedence     = 2
  decision       = "allow"

  include {
    email_domain = [var.allowed_email_domain]
  }

  require {
    login_method = ["f1fef5f2-ed08-4660-aa94-243a20958391"]
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "application_id" {
  description = "Cloudflare Access Application ID"
  value       = cloudflare_zero_trust_access_application.banking_api.id
}

output "application_aud" {
  description = "Application Audience tag for JWT validation"
  value       = "0d90066fa1fefca330e64ffe10cd01e0b6b79cdd999ddbc05dff1bb1ccd4918c"
}

output "tunnel_id" {
  description = "Cloudflare Tunnel ID - banking-zero-trust"
  value       = "7c95c5c5-982d-4c56-a3f5-0e7c62550e30"
}

output "tunnel_cname" {
  description = "CNAME value for DNS routing"
  value       = "7c95c5c5-982d-4c56-a3f5-0e7c62550e30.cfargotunnel.com"
}
