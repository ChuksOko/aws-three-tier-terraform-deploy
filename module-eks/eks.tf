# module-eks/eks.tf 

# checkov:skip=CKV_AWS_39:Public endpoint required for ArgoCD external access.
# Compensating controls: CIDR restriction + full logging + private endpoint enabled.
resource "aws_eks_cluster" "eks" {
  name     = "${var.environment}-${var.cluster_name}"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = concat(var.public_subnet_ids, var.private_subnet_ids)
    endpoint_public_access  = true
    endpoint_private_access = true
    public_access_cidrs     = var.allowed_cidr_blocks   # Restrict access
  }

  # MUST be outside vpc_config
  enabled_cluster_log_types = [
    "api",               # API server requests
    "audit",             # Full audit trail
    "authenticator",     # IAM authentication logs
    "controllerManager", # Controller decisions
    "scheduler"          # Pod scheduling
  ]

  tags = {
    Name        = "${var.environment}-${var.cluster_name}"
    Environment = var.environment
  }
}

# variables.tf (module)

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the EKS public endpoint"
  type        = list(string)
  # DO NOT leave a real IP here in production — override via tfvars or CI/CD
  default     = ["203.0.113.0/32"]
}