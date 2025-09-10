resource "aws_kms_key" "ebs_kms" {
    description = "KMS key for EBS encryption"
    deletion_window_in_days = 7
    enable_key_rotation = true
    key_usage               = "ENCRYPT_DECRYPT"


    policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
        # Keep the root as ultimate admin (enables IAM policies)
        {
            Sid       = "EnableIAMUserPermissions",
            Effect    = "Allow",
            Principal = { AWS = "arn:aws:iam::${var.account_id}:root" },
            Action    = "kms:*",
            Resource  = "*"
        },

        # Key administrators (no decrypt/data-key by default)
        {
            Sid       = "AllowKeyAdministration",
            Effect    = "Allow",
            Principal = { AWS = var.ebs_key_admin_arns },
            Action    = [
                "kms:DescribeKey","kms:List*","kms:Get*",
                "kms:CreateAlias","kms:UpdateAlias","kms:DeleteAlias",
                "kms:TagResource","kms:UntagResource",
                "kms:EnableKey","kms:DisableKey","kms:UpdateKeyDescription",
                "kms:PutKeyPolicy","kms:ScheduleKeyDeletion","kms:CancelKeyDeletion",
                "kms:EnableKeyRotation","kms:CreateGrant","kms:RevokeGrant"
            ],
            Resource  = "*"
        },

        # Allow designated principals to USE the key **only via EC2/EBS**
        {
            Sid       = "AllowUseForEBSViaEC2",
            Effect    = "Allow",
            Principal = { AWS = var.ebs_key_user_arns },
            Action    = [
            "kms:Encrypt","kms:Decrypt","kms:ReEncrypt*",
            "kms:GenerateDataKey*","kms:DescribeKey"
            ],
            Resource  = "*",
            Condition = {
            StringEquals = {
                # Limit cryptographic use to the EC2 service in this region (covers EBS volumes/snapshots)
                "kms:ViaService" = "ec2.${var.region}.amazonaws.com"
            }
            }
        },

        # Let the EC2 service create the persistent grants EBS needs (no direct decrypt)
        {
            Sid       = "AllowEC2ToCreateGrantsForEBS",
            Effect    = "Allow",
            Principal = { Service = "ec2.amazonaws.com" },
            Action    = [
            "kms:CreateGrant"
            ],
            Resource  = "*",
            Condition = {
                Bool = {
                    "kms:GrantIsForAWSResource" = "true"
                },
                StringEquals = {
                    "kms:ViaService" = "ec2.${var.region}.amazonaws.com"
                }
            }
        },
        # Explicit Deny: block decrypt/data-key ops unless EBS-via-EC2
        # {
        #     Sid      = "DenyDecryptWithoutEBSorEnclaveAttestation",
        #     Effect   = "Deny",
        #     NotPrincipal = { AWS = var.ebs_key_admin_arns },
        #     Action   = [
        #         "kms:Decrypt",
        #         "kms:GenerateDataKey",
        #         "kms:GenerateDataKeyWithoutPlaintext",
        #         "kms:GenerateRandom",
        #         "kms:ReEncrypt*"
        #     ],
        #     Resource = "*",
        #     Condition = {
        #         StringNotEquals = {
        #             "kms:ViaService" = "ec2.${var.region}.amazonaws.com"
        #         }
        #     }
        # }

        ]
    })
    tags = {
        Name        = "ebs_kms_key"
        Environment = var.environment
    }
  
}

resource "aws_kms_alias" "ebs_kms" {
  name          = "alias/ebs-default"
  target_key_id = aws_kms_key.ebs_kms.id
}