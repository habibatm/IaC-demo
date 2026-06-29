# DevSecOps CoE demo - improved Terraform sample
# This is still demo code. Validate against client/cloud standards before reuse.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

variable "admin_cidr" {
  description = "Approved corporate/admin CIDR for emergency access in demo"
  type        = string
  default     = "10.0.0.0/24"
}

resource "aws_s3_bucket" "demo" {
  bucket = "pwc-devsecops-demo-secure-bucket"
}

resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "demo" {
  bucket = aws_s3_bucket.demo.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_security_group" "restricted_admin" {
  name        = "restricted-admin-demo"
  description = "Improved demo security group"

  ingress {
    description = "SSH limited to approved admin CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "demo" {
  ami                         = "ami-1234567890abcdef0"
  instance_type               = "t2.micro"
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.restricted_admin.id]

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "devsecops-improved-demo"
  }
}
