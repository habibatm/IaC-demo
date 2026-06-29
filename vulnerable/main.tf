# DevSecOps CoE demo - intentionally vulnerable Terraform
# Do NOT run terraform apply. This file is for static IaC scanning only.

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

resource "aws_s3_bucket" "demo" {
  bucket = "pwc-devsecops-demo-insecure-bucket"
}

# Public access controls are deliberately disabled.
resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Deliberately grants public read access to all objects in the bucket.
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.demo.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadForDemo"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.demo.arn}/*"
    }]
  })
}

# Security group exposes admin ports to the Internet.
resource "aws_security_group" "open_admin" {
  name        = "open-admin-demo"
  description = "Insecure demo security group"

  ingress {
    description = "SSH open to the Internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP open to the Internet"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound traffic allowed"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "demo" {
  ami                         = "ami-1234567890abcdef0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.open_admin.id]

  # Deliberately allows IMDSv1.
  metadata_options {
    http_tokens = "optional"
  }

  # Deliberately disables root volume encryption.
  root_block_device {
    encrypted = false
  }

  tags = {
    Name = "devsecops-insecure-demo"
  }
}
