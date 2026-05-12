variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
  default     = "a17e1aa5d99aaa0650225a20f83a6fbd"
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for skybound02.online"
  type        = string
  default     = "4bc60d85c13fc503194662479d868155"
}

variable "team_domain" {
  description = "Cloudflare Zero Trust team domain"
  type        = string
  default     = "chuksoko"
}

variable "banking_api_domain" {
  description = "Banking API hostname"
  type        = string
  default     = "banking-api.skybound02.online"
}

variable "allowed_email_domain" {
  description = "Email domain allowed to access the banking API"
  type        = string
  default     = "gmail.com"
}