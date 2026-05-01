
resource "aws_db_instance" "mysql_db_instance" {
  identifier             = "${var.environment}-mysql-db"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = var.db_instance_class
  allocated_storage      = var.db_allocated_storage
  storage_type           = "gp3"                         # gp3 is cheaper + faster
  db_subnet_group_name   = aws_db_subnet_group.mysql_subnet_group.name
  vpc_security_group_ids = [var.aws_security_group_ids]
  username               = var.db_username
  password               = var.db_password
  db_name                = var.db_name
 
  storage_encrypted                   = true    # Encrypt at rest with AES-256
  skip_final_snapshot                 = false   # Keep snapshot when destroyed
  final_snapshot_identifier           = "${var.environment}-mysql-final-snapshot"
  deletion_protection                 = true    # Prevent accidental deletion
  multi_az                            = true    # Standby replica for HA
  auto_minor_version_upgrade          = true    # Apply security patches
  iam_database_authentication_enabled = true    # IAM-based auth enabled
  enabled_cloudwatch_logs_exports     = ["error", "general", "slowquery"]
 
  lifecycle { ignore_changes = [password] }
}
