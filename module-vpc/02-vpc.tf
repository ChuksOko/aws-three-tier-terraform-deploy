resource "aws_vpc" "vpc-main" {
  cidr_block           = var.vpc_cidrblock
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
  assign_generated_ipv6_cidr_block = false
 
  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}
 
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.environment}-flow-logs"
  retention_in_days = 90
}
 
resource "aws_iam_role" "flow_log_role" {
  name = "${var.environment}-vpc-flow-log-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect="Allow", Principal={ Service="vpc-flow-logs.amazonaws.com" },
      Action="sts:AssumeRole" }]
  })
}
 
resource "aws_flow_log" "vpc_flow" {
  vpc_id          = aws_vpc.vpc-main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
}
