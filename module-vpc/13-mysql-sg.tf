resource "aws_security_group" "mysql_sg" {
  name        = "${var.environment}-mysql-sg"
  description = "Security group for MySQL RDS instance"
  vpc_id      = aws_vpc.vpc-main.id
 
  ingress {
    description = "MySQL from within VPC only"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidrblock]
  }
 
  # No egress rule = implicit deny all outbound
  # RDS never needs to initiate outbound connections
  # Remove the catch-all egress block entirely
 
  tags = {
    Name        = "${var.environment}-mysql-sg"
    Environment = var.environment
  }
}
