resource "aws_subnet" "public_subnet" {
  count             = var.create_subnet ? var.countsub : 0
  vpc_id            = aws_vpc.vpc-main.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
  cidr_block        = "192.168.${count.index}.0/24"
  map_public_ip_on_launch = false   # No automatic public IPs
 
  tags = {
    Name        = "${var.environment}-public-subnet-${count.index+1}"
    Environment = var.environment
    "kubernetes.io/role/elb" = "1"
    "kubernetes.io/cluster/${var.environment}-${var.cluster_name}" = "owned"
  }
}
 
# module-vpc/02-vpc.tf — AFTER (add default SG lockdown)
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.vpc-main.id
  # No ingress or egress rules = deny all traffic
  # Forces all resources to use explicit, reviewed security groups
  tags = { Name = "${var.environment}-default-sg-locked" }
}
