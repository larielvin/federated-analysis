data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

    filter {
        name   = "virtualization-type"
        values = ["hvm"]
    }

}

resource "aws_instance" "ubuntu_instance" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  availability_zone    = element(module.vpc.azs, 0)
  subnet_id     = module.vpc.public_subnets[0]
  key_name = aws_key_pair.generated.key_name
#   iam_instance_profile = 
  vpc_security_group_ids = [aws_security_group.allow_ssh_https.id]
  associate_public_ip_address = true
  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp2"
    encrypted = true
    kms_key_id = aws_kms_key.ebs_kms.arn
  }



  tags = {
    Name        = "UbuntuInstance"
    Environment = var.environment
  }

  
}