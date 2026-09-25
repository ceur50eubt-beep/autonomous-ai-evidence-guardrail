resource "aws_kms_key" "ai_signer" {
  description              = "Asymmetric Key for Autonomous AI Evidence Signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  deletion_window_in_days  = 7
  enable_key_rotation      = false

  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
    Project     = "autonomous-ai-evidence-guardrail"
  }
}

resource "aws_kms_alias" "ai_signer_alias" {
  name          = "alias/ai-audit-signer"
  target_key_id = aws_kms_key.ai_signer.key_id
}

output "kms_key_arn" {
  value = aws_kms_key.ai_signer.arn
}
