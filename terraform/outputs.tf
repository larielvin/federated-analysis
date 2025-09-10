output "instance" {
  value = aws_instance.ubuntu_instance
}

output "aws_kms_key" {
  value = aws_kms_key.ebs_kms.arn
}
