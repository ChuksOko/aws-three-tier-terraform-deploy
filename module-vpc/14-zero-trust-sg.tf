# =============================================================================
# Zero Trust Network Security Groups
# =============================================================================
# As part of the Zero Trust Identity Pivot, all static ingress rules for
# port 443 (HTTPS) and port 22 (SSH) have been removed from all security
# groups. Network access is now controlled exclusively by Cloudflare Tunnel.
#
# BEFORE (Static perimeter model):
#   - Port 443 open to 0.0.0.0/0 — anyone could reach the API
#   - Port 22 open to specific CIDRs — SSH access via IP whitelist
#   - Trust was based on network location
#
# AFTER (Zero Trust model):
#   - No inbound ports open on any security group
#   - All traffic enters via Cloudflare Tunnel (outbound-only connection)
#   - Trust is based on identity (Google OIDC) + device posture (Lambda check)
#   - A developer in a coffee shop can access the API without VPN,
#     but only if their device passes the health check
# =============================================================================

# -----------------------------------------------------------------------------
# EKS Worker Node Security Group - Zero Trust Posture
# Replaces any previous security group that had port 443/22 open
# -----------------------------------------------------------------------------
resource "aws_security_group" "eks_zero_trust_sg" {
  name        = "${var.environment}-eks-zero-trust-sg"
  description = "Zero Trust security group for EKS worker nodes. No static ingress rules. All external access via Cloudflare Tunnel only."
  vpc_id      = aws_vpc.vpc-main.id

  # -------------------------------------------------------------------------
  # NO ingress rules for port 443 (HTTPS)
  # REMOVED: was previously open to 0.0.0.0/0
  # REPLACED BY: Cloudflare Tunnel outbound connection
  # External users authenticate via Google OIDC before any traffic
  # reaches the cluster
  # -------------------------------------------------------------------------

  # -------------------------------------------------------------------------
  # NO ingress rules for port 22 (SSH)
  # REMOVED: was previously open to specific CIDRs
  # REPLACED BY: AWS Systems Manager Session Manager (SSM)
  # SSM provides shell access without opening port 22 anywhere
  # -------------------------------------------------------------------------

  # -------------------------------------------------------------------------
  # Internal cluster communication only
  # Pods can communicate with each other within the VPC
  # No external internet access initiated from worker nodes
  # -------------------------------------------------------------------------
  ingress {
    description = "Internal cluster communication within VPC only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidrblock]
  }

  # -------------------------------------------------------------------------
  # Egress: allow outbound for Cloudflare Tunnel connection
  # cloudflared initiates an OUTBOUND connection to Cloudflare edge
  # This is the only way traffic enters — no inbound ports needed
  # -------------------------------------------------------------------------
  egress {
    description = "Outbound for Cloudflare Tunnel and AWS API calls"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name                                                       = "${var.environment}-eks-zero-trust-sg"
    Environment                                                = var.environment
    ZeroTrust                                                  = "true"
    "kubernetes.io/cluster/${var.environment}-${var.cluster_name}" = "owned"
  }
}

# -----------------------------------------------------------------------------
# Application Load Balancer Security Group - Zero Trust Posture
# In Zero Trust model, the ALB is REMOVED entirely
# Cloudflare Tunnel replaces the ALB as the ingress path
# This resource documents the BEFORE state for reference
# -----------------------------------------------------------------------------
# BEFORE (removed):
# resource "aws_security_group" "alb_sg" {
#   ingress {
#     from_port   = 443
#     to_port     = 443
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]   # STATIC — entire internet
#   }
#   ingress {
#     from_port   = 80
#     to_port     = 80
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]   # STATIC — entire internet
#   }
# }
#
# AFTER: No ALB security group needed
# Cloudflare Tunnel handles all ingress with Zero Trust policies applied
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# SSH Bastion Security Group - Zero Trust Posture
# In Zero Trust model, the bastion host is REMOVED entirely
# AWS SSM Session Manager replaces SSH for all shell access
# -----------------------------------------------------------------------------
# BEFORE (removed):
# resource "aws_security_group" "bastion_sg" {
#   ingress {
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["OFFICE_IP/32"]   # STATIC — IP whitelist
#   }
# }
#
# AFTER: No bastion security group needed
# SSM Session Manager provides shell access without port 22
# Access requires valid AWS IAM credentials — identity-based, not IP-based
# -----------------------------------------------------------------------------