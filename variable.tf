 variable "vpc_cidrblock" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "192.168.0.0/16"
  
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "staging"
  
}

variable "create_subnet" {
  description = "Flag to create a subnet"
  type        = bool
  default     = true
}

variable "countsub" {
  description = "Number of subnets to create"
  type        = number
  default     = 2
  
}
variable "create_elastic_ip" {
  description = "Flag to create Elastic IPs"
  type        = bool\
  default     = true
}


variable "desired_size" {
  description = "Desired size of the EKS node group"
  type        = number
  default     = 2
}

variable "max_size" {
  description = "Maximum size of the EKS node group"
  type        = number
  default     = 6
}

variable "min_size" {
  description = "Minimum size of the EKS node group"
  type        = number
  default     = 2 
}

variable "instance_types" {
  description = "Instance types for the EKS node group"
  type        = list(string)
  default     = ["t2.micro"]    
} 

variable "capacity_type" {
  description = "Capacity type for the EKS node group"
  type        = string
  default     = "ON_DEMAND"
}
variable "eks_version" {
  description = "EKS cluster version"
  type        = string
  default     = "1.32"
}
variable "ami_type" {
  description = "AMI type for the EKS node group"
  type        = string
  default     = "AL2_x86_64" # Use AL2_x86_64 for x86 instances, AL2_ARM_64 for ARM instances
}

variable "label_one" {
  description = "Label for the EKS node group"
  type        = string
  default     = "system"
}

variable "zone_name" {
  description = "Name of the DNS zone"
  type        = string
  default     = "skybound02.online"
}

variable "domain-name" {
  description = "Domain name to be created"
  type        = string
  default     = "skybound02.online"
}

variable "namecheap_api_user" {
  description = "Namecheap API user"
  type        = string
  default     = "Jomek"
}

variable "namecheap_api_key" {
  description = "Namecheap API key - set via TF_VAR_ env var or tfvars file"
  type        = string
  # No default - must be supplied at runtime, never hardcoded
}
variable "namecheap_username" {
  description = "Namecheap username - set via TF_VAR_namecheap_username"
  type        = string
}
variable "db_password" {
  description = "RDS password - injected from AWS Secrets Manager or CI secret"
  type        = string
  sensitive   = true   # Redacts value from all Terraform logs/plan output
}
 
# In GitHub Actions — store in repo secrets, not in code:
# Settings → Secrets → TF_VAR_namecheap_api_key
# Settings → Secrets → TF_VAR_db_password
#
# Then in cicd.yaml:
# env:
#   TF_VAR_namecheap_api_key: ${{ secrets.TF_VAR_NAMECHEAP_API_KEY }}
#   TF_VAR_db_password: ${{ secrets.TF_VAR_DB_PASSWORD }}


#===========

variable "db_instance_class" {
  description = "Instance class for the RDS database"
  type        = string
  default     = "db.t3.micro" 
}

variable "db_allocated_storage" {
  description = "Storage allocated to the DB instance (in GB)"
  type        = number
  default     = 20
}

# variable "db_subnet_group_name" {
#   description = "Name of the DB subnet group"
#   type        = string
#   default     = "my-db-subnet-group"
# }

variable "db_username" {
  description = "Username for the database"
  type        = string
  default     = "admin"
}

#variable "db_password" {
#  description = "Password for the database"
#  type        = string
#  default     = "password123"
#  sensitive   = true
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "production_db"
}
variable "cluster_name" {
  description = "The name of the EKS cluster"
  type        = string
  default     = "eks-cluster"
}

variable "repository_name" {
  description = "Name of the ECR repository"
  type        = string
  default     = "eks-repository"
  
}

variable "email" {
  description = "Email address for notifications and certificates"
  type        = string
  default     = "support@skybound02.online"
}