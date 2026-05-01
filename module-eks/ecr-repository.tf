# module-eks/ecr-repository.tf

resource "aws_ecr_repository" "bank_backend" {
  name = "bank-backendapi"
  image_tag_mutability = "IMMUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  encryption_configuration {
    encryption_type = "KMS"
    kms_key = aws_kms_key.ecr_key.arn
  }
}

resource "aws_ecr_repository" "bank_frontend" {
  name = "bank-frontend"
  image_tag_mutability = "IMMUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  encryption_configuration {
    encryption_type = "KMS"
    kms_key = aws_kms_key.ecr_key.arn
  }
}