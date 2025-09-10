resource "null_resource" "setup_docker" {
  depends_on = [aws_instance.ubuntu_instance]

  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = file(var.privatekeypath)
    host        = aws_instance.ubuntu_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      # make directory 
      "mkdir -p /home/ubuntu/analysis",
      "git clone https://${var.github_token}@github.com/elvinlari/federated-analysis-dev.git /home/ubuntu/analysis",
      "git -C /home/ubuntu/analysis pull || echo 'git pull failed, continuing'",

      # System prep
      "sudo apt-get update -y",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl software-properties-common gnupg lsb-release pass gpg build-essential age jq python3-pip",

      # Docker group (safe creation)
      "getent group docker || sudo groupadd docker",
      "sudo usermod -aG docker ubuntu",

      # Add Docker GPG key and repository
      "if [ ! -f /usr/share/keyrings/docker-archive-keyring.gpg ]; then curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; fi",     
      "echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu jammy stable' | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
      "sudo apt-get update -y",

      # Install Docker & Compose v2
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",

      # Confirm install
      "docker --version",
      "docker compose version",

      # Nitro
      "echo 'heeeeeeey'",
      "uname -r",
      "grep /boot/config-$(uname -r) -e NITRO_ENCLAVES",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends linux-modules-extra-aws",
      "ls -l /usr/lib/modules/$(uname -r)/kernel/drivers/virt/nitro_enclaves/nitro_enclaves.ko",
      "sudo insmod /usr/lib/modules/$(uname -r)/kernel/drivers/virt/nitro_enclaves/nitro_enclaves.ko",
      "lsmod | grep nitro_enclaves",
      "git clone https://github.com/aws/aws-nitro-enclaves-cli.git",
      "cd aws-nitro-enclaves-cli",
      "THIS_USER=\"$(whoami)\"",
      # Remove driver insertion logic from bootstrap/nitro-cli-config
      "sed -i '/# Remove an older driver/,/The driver is not visible./d' bootstrap/nitro-cli-config",
      # Remove insmod line from bootstrap/env.sh
      "sed -i '/lsmod | grep -q nitro_enclaves/,/nitro_enclaves.ko/d' bootstrap/env.sh",
      # Adjust Makefile install target
      "sed -i 's/install: install-tools nitro_enclaves/install: install-tools/' Makefile",
      "sed -i '/extra\\/nitro_enclaves/d' Makefile",
      "export NITRO_CLI_INSTALL_DIR=/",
      "sudo make nitro-cli",
      "sudo make vsock-proxy",
      "sudo make NITRO_CLI_INSTALL_DIR=/ install",
      "source /etc/profile.d/nitro-cli-env.sh",
      "echo source /etc/profile.d/nitro-cli-env.sh >> ~/.bashrc",
      "nitro-cli --version",
      "sudo reboot",
    ]
    on_failure = "continue"
  }

}



# Give the OS a moment to actually go down
resource "time_sleep" "let_reboot_start" {
  depends_on       = [null_resource.setup_docker]
  create_duration  = "30s"
}

resource "null_resource" "run_nitro" {
  depends_on = [time_sleep.let_reboot_start]

  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = file(var.privatekeypath)
    host        = aws_instance.ubuntu_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo modprobe nitro_enclaves",
      "sudo modprobe vhost_vsock",
      "lsmod | grep nitro_enclaves || echo 'driver NOT loaded'",
      "test -e /dev/nitro_enclaves && echo '/dev/nitro_enclaves OK' || echo 'device missing'",
      "test -f /sys/module/nitro_enclaves/parameters/ne_cpus && echo 'sysfs OK' || echo 'sysfs missing'",
      "sudo install -d -m 0755 -o root -g root /run/nitro_enclaves",
      "sudo install -d -m 0755 /var/log/nitro_enclaves",
      "sudo install -m 0644 /dev/null /var/log/nitro_enclaves/nitro_enclaves.log",
      "cd /home/ubuntu/analysis",
      "make data-generate",
      "make train",
      "make copy_train_output",
      "make keys-generate",
      "make keys-build",
      "sudo sed -i -E 's/^( *memory_mib:).*/\\1 0/' /etc/nitro_enclaves/allocator.yaml",
      "sudo sed -i -E 's/^( *cpu_count:).*/\\1 2/'       /etc/nitro_enclaves/allocator.yaml",
      "sudo systemctl restart nitro-enclaves-allocator.service",
      "sudo sed -i -E 's/^( *memory_mib:).*/\\1 9216/' /etc/nitro_enclaves/allocator.yaml",
      "sudo sed -i -E 's/^( *cpu_count:).*/\\1 4/'       /etc/nitro_enclaves/allocator.yaml",
      "sudo systemctl restart nitro-enclaves-allocator.service",
      "make append-pcr0",
      "make run-enclave",
      "sudo ss -lpnA vsock | grep -w ':7002'",
      "make party-download",
      "make party-verify",
      "make party-rewrap",
      "make party-collect",
    ]
    
  }

}


resource "null_resource" "run_parties" {
  depends_on = [null_resource.run_nitro]

  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = file(var.privatekeypath)
    host        = aws_instance.ubuntu_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "cd /home/ubuntu/analysis",
      "git pull",
      "make party-unarchive-keys",
      "make party-copy-keys",
      "make party-copy-model",
      "make party-encrypt-data",
      "make server-copy-model",
      "make party-send-data-to-server",
      "make server-inference",
      "make party-copy-decrypt-assets",
      "make party-decrypt",
    ]
    
  }

}
