variable "bucket_prefix" {
  type    = string
  default = "ai-agent-evidence-worm"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "audit_bucket" {
  bucket        = "${var.bucket_prefix}-${random_id.suffix.hex}"
  force_destroy = false

  object_lock_enabled = true

  tags = {
    Environment = "production"
    Security    = "WORM-Compliance"
  }
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.audit_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "worm_lock" {
  bucket = aws_s3_bucket.audit_bucket.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

output "bucket_arn" {
  value = aws_s3_bucket.audit_bucket.arn
}
