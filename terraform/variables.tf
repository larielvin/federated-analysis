variable "access_key" {}

variable "secret_key" {}

variable "region" {
  default = "eu-north-1"
}

variable "vpc_name" {
  default = "lynq-vpc"
}

variable "environment" {
  default = "dev"
}

variable "instance_type" {
  default = "t3.micro"
}

variable "publickeypath" {
  description = "Path to the public key file"
  default     = "~/.ssh/id_rsa.pub" 
}

variable "privatekeypath" {
  description = "Path to the private key file"
  default     = "~/.ssh/id_rsa" 
  
}

variable "volume_size" {
  description = "Size of the root volume in GB"
  default     = 8
}

variable "github_token" {
  description = "GitHub token for accessing private repositories"
  type        = string
#   sensitive   = true
}

variable "account_id" {
  description = "AWS Account ID"
  default     = "272495906973"
}

variable "ebs_key_admin_arns" {
  description = "List of IAM ARNs allowed to administer (NOT decrypt with) this key"
  type        = list(string)
  default     = ["arn:aws:iam::272495906973:user/elvin"]
}

variable "ebs_key_user_arns" {
  description = "List of IAM ARNs allowed to use the key (encrypt/decrypt) for EBS via EC2"
  type        = list(string)
  default     = ["arn:aws:iam::272495906973:user/elvin"]
}