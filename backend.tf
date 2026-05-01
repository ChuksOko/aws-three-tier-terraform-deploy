terraform {
  backend "s3" {
    bucket         = "skybound02"
    key            = "s3-cicd/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-lock"
    encrypt        = true
  }
}
