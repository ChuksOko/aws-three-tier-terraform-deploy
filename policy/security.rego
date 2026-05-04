package main

import future.keywords.if
import future.keywords.in

deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  egress := resource.values.egress[_]
  egress.cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf(
    "POLICY VIOLATION [Anti-Exfiltration]: Security group '%s' has an egress rule open to 0.0.0.0/0. Database security groups must not allow unrestricted outbound traffic.",
    [resource.name]
  )
}

deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_db_instance"
  not resource.values.storage_encrypted == true
  msg := sprintf(
    "POLICY VIOLATION [Encryption Enforcement]: RDS instance '%s' does not have storage_encrypted = true. All database instances must encrypt data at rest.",
    [resource.name]
  )
}

deny[msg] {
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_eks_cluster"
  vpc_config := resource.values.vpc_config[_]
  vpc_config.endpoint_public_access == true
  not valid_cidr_restriction(vpc_config)
  msg := sprintf(
    "POLICY VIOLATION [Public Access Prevention]: EKS cluster '%s' has endpoint_public_access = true but no CIDR restriction in public_access_cidrs. Either disable public access or restrict to approved IP ranges.",
    [resource.name]
  )
}

valid_cidr_restriction(vpc_config) {
  cidrs := vpc_config.public_access_cidrs
  count(cidrs) > 0
  not "0.0.0.0/0" in cidrs
}
