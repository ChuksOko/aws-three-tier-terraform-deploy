# =============================================================================
# Zero Trust Device Health Check - Lambda Terraform Deployment
# =============================================================================
# This deploys the device_health_check.py Lambda function as an AWS API
# Gateway Lambda Authorizer. Every request to the banking API passes through
# this function before reaching the application layer.
# =============================================================================

# -----------------------------------------------------------------------------
# Package the Lambda function code into a zip file
# -----------------------------------------------------------------------------
data "archive_file" "device_health_check" {
  type        = "zip"
  source_file = "${path.module}/device_health_check.py"
  output_path = "${path.module}/device_health_check.zip"
}

# -----------------------------------------------------------------------------
# KMS key for Lambda environment variable encryption
# -----------------------------------------------------------------------------
resource "aws_kms_key" "lambda_key" {
  description             = "KMS key for Lambda environment encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.environment}-lambda-kms-key"
    Environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# IAM role for the Lambda function
# Follows least-privilege — only CloudWatch Logs permissions granted
# -----------------------------------------------------------------------------
resource "aws_iam_role" "device_health_check_role" {
  name = "${var.environment}-device-health-check-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name        = "${var.environment}-device-health-check-role"
    Environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# IAM policy - CloudWatch Logs only
# Lambda does not need any other AWS permissions
# -----------------------------------------------------------------------------
resource "aws_iam_role_policy" "device_health_check_policy" {
  name = "${var.environment}-device-health-check-policy"
  role = aws_iam_role.device_health_check_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Lambda function
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "device_health_check" {
  function_name    = "${var.environment}-device-health-check"
  filename         = data.archive_file.device_health_check.output_path
  source_code_hash = data.archive_file.device_health_check.output_base64sha256
  role             = aws_iam_role.device_health_check_role.arn
  handler          = "device_health_check.lambda_handler"
  runtime          = "python3.12"
  timeout          = 10
  memory_size      = 128
  kms_key_arn      = aws_kms_key.lambda_key.arn

  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # Reserved concurrency prevents noisy-neighbour issues
  reserved_concurrent_executions = 10

  environment {
    variables = {
      ENVIRONMENT = var.environment
      LOG_LEVEL   = "INFO"
    }
  }

  tracing_config {
    mode = "Active"   # AWS X-Ray tracing enabled
  }

  tags = {
    Name        = "${var.environment}-device-health-check"
    Environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group with 90-day retention
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "device_health_check" {
  name              = "/aws/lambda/${aws_lambda_function.device_health_check.function_name}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.lambda_key.arn

  tags = {
    Name        = "${var.environment}-device-health-check-logs"
    Environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# SQS Dead Letter Queue for failed Lambda invocations
# -----------------------------------------------------------------------------
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${var.environment}-device-health-check-dlq"
  message_retention_seconds = 1209600   # 14 days
  kms_master_key_id         = aws_kms_key.lambda_key.arn

  tags = {
    Name        = "${var.environment}-device-health-check-dlq"
    Environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# API Gateway - exposes the Lambda as an HTTP endpoint
# -----------------------------------------------------------------------------
resource "aws_api_gateway_rest_api" "zero_trust_authorizer" {
  name        = "${var.environment}-zero-trust-authorizer"
  description = "Zero Trust device health check API Gateway"

  tags = {
    Name        = "${var.environment}-zero-trust-authorizer"
    Environment = var.environment
  }
}

resource "aws_api_gateway_resource" "health_check" {
  rest_api_id = aws_api_gateway_rest_api.zero_trust_authorizer.id
  parent_id   = aws_api_gateway_rest_api.zero_trust_authorizer.root_resource_id
  path_part   = "health-check"
}

resource "aws_api_gateway_method" "health_check_post" {
  rest_api_id   = aws_api_gateway_rest_api.zero_trust_authorizer.id
  resource_id   = aws_api_gateway_resource.health_check.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "health_check_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.zero_trust_authorizer.id
  resource_id             = aws_api_gateway_resource.health_check.id
  http_method             = aws_api_gateway_method.health_check_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.device_health_check.invoke_arn
}

resource "aws_api_gateway_deployment" "zero_trust_authorizer" {
  rest_api_id = aws_api_gateway_rest_api.zero_trust_authorizer.id

  depends_on = [
    aws_api_gateway_integration.health_check_lambda
  ]
}

resource "aws_api_gateway_stage" "zero_trust_authorizer" {
  deployment_id = aws_api_gateway_deployment.zero_trust_authorizer.id
  rest_api_id   = aws_api_gateway_rest_api.zero_trust_authorizer.id
  stage_name    = var.environment

  tags = {
    Name        = "${var.environment}-zero-trust-authorizer-stage"
    Environment = var.environment
  }
}

# Allow API Gateway to invoke the Lambda function
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.device_health_check.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.zero_trust_authorizer.execution_arn}/*/*"
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "lambda_function_name" {
  description = "Name of the device health check Lambda function"
  value       = aws_lambda_function.device_health_check.function_name
}

output "lambda_function_arn" {
  description = "ARN of the device health check Lambda function"
  value       = aws_lambda_function.device_health_check.arn
}

output "api_gateway_endpoint" {
  description = "API Gateway endpoint for the device health check"
  value       = "${aws_api_gateway_stage.zero_trust_authorizer.invoke_url}/health-check"
}