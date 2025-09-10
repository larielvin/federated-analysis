resource "aws_key_pair" "generated" {
  key_name   = "my-key-pair"
  public_key = file(var.publickeypath) # Adjust the path to your public key file
  
}