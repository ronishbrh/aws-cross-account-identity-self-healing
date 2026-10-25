terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "default"
}

provider "aws" {
  alias   = "target"
  region  = "us-east-1"
  profile = "identity-target"
}

data "aws_caller_identity" "current" {}

data "aws_caller_identity" "target" {
  provider = aws.target
}

output "monitoring_account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "target_account_id" {
  value = data.aws_caller_identity.target.account_id
}

resource "aws_sqs_queue" "identity_findings_dlq" {
  name                      = "identity-self-healing-findings-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "identity_findings" {
  name                       = "identity-self-healing-findings"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 60
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.identity_findings_dlq.arn
    maxReceiveCount     = 5
  })
}

output "identity_findings_queue_url" {
  value = aws_sqs_queue.identity_findings.url
}

output "identity_findings_dlq_url" {
  value = aws_sqs_queue.identity_findings_dlq.url
}


resource "aws_iam_role_policy" "lambda_send_findings" {
  name = "identity-self-healing-send-findings"
  role = "identity-self-healing-handler-role-vuxcrqqt"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.identity_findings.arn
      }
    ]
  })
}
