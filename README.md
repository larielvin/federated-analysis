# Privacy Preserving Federated Analysis for Agricultural Grant/Credit Risk Determination

## Overview
This project is deployed to AWS using Terraform. The steps below cover local setup, configuring AWS credentials, planning, applying, and destroying infrastructure.

## Prerequisites
- **Terraform** ≥ 1.5
- An AWS account with sufficient IAM permissions to create the required resources

## Repo layout
```
.
├─ data-generation/               # literature-anchored synthetic dataset generation
├─ fed-analysis-data-encrypt/     # per-party data encryption for inference
├─ fed-analysis-keys/             # FHE keys generation and sealing
├─ fed-analysis-output-decrypt/   # per-party server output decryption
├─ fed-analysis-server-inference/ # server inference on encrypted data
├─ fed-analysis-train/            # server model training on clear data
├─ smartcontract/                 # IPFS and blockchain anchoring
├─ Makefile                       # make commands for running the project
├─ terraform/                     # terraform configurations for AWS deployment
│  ├─ secrets.auto.tfvars         # secret file containg credentials
│  ├─ main.tf                     # main terraform file
│  └─ ...
└─ README.md           
```

## Configure AWS credentials and secrets

### Create Local `secrets.auto.tfvars` file
Terraform automatically loads files ending with `.auto.tfvars`.  
**Do not commit** secrets to git. Use this only on your machine, never in CI.

Create a file named `secrets.auto.tfvars` and save it in the terraform directory (listed in `.gitignore`; see below):

```hcl
# secrets.auto.tfvars  (LOCAL USE ONLY — DO NOT COMMIT)
region              = "eu-west-2"
access_key          = "<YOUR_AWS_ACCESS_KEY_ID>"
secret_key          = "<YOUR_AWS_SECRET_ACCESS_KEY>"
publickeypath       = "~/.ssh/id_rsa.pub"
privatekeypath      = "~/.ssh/id_rsa"
github_token        = "ghp_....." # needed for cloning this repo in the AWS ec2 server
volume_size         = 100
instance_type       = "c5.2xlarge" # this has nitro enclave capability

```

## Initialize
From the terraform directory run this.

```bash
terraform init
```
If you use a remote backend (S3 + DynamoDB), ensure `backend` config in `main.tf` is correct (bucket name, region, key path, etc.) before running `init`.
For this project I used local.

## Validate
```bash
terraform validate
```

## Plan
- If you used `secrets.auto.tfvars`, Terraform will load `secrets.auto.tfvars` automatically:
  ```bash
  terraform plan 
  ```

## Apply
```bash
terraform apply 
```
Type `yes` when prompted.

## Destroy
When you need to tear everything down:
```bash
terraform destroy 
```

## Common environment overrides
You can pass variables directly:
```bash
terraform plan -var="aws_region=eu-west-1" -var="project_name=my-stack"
```

## Troubleshooting
- **Expired credentials**: Re-authenticate (re-issue session tokens).
- **Access denied**: Verify your IAM permissions and correct AWS account.
- **State lock** (with remote backend): If a previous run crashed, release the lock from DynamoDB (or wait until it expires).
- **Wrong region**: Ensure `aws_region` and your AWS profile default region match the intended environment.

## Security & compliance notes
- Never commit secrets to git. 
- If you must keep `secrets.auto.tfvars` locally, ensure it’s listed in `.gitignore` and stored securely.
- Consider setting `variable ... { sensitive = true }` for all secret inputs.
- Consider a remote backend (S3 + DynamoDB) for shared state and locking.

---

## Quick start (copy/paste)
```bash
# 1) Populate secrets.auto.tfvars file

# 2) Terraform workflow
terraform init
terraform validate
terraform plan 
terraform apply 
```
This will provision the AWS server, install all dependencies, run the make commands for the following:

* Data generation:  
  ```bash
  cd /home/ubuntu/analysis
  make data-generate
  ```

* Model training:  
  ```bash
  make train
  make copy_train_output
  ```

* FHE key management:  
  ```bash
  make keys-generate
  make keys-build
  ```

* Nitro Enclave configuration:  
  ```bash
  sudo sed -i -E 's/^( *memory_mib:).*/\1 0/' /etc/nitro_enclaves/allocator.yaml
  sudo sed -i -E 's/^( *cpu_count:).*/\1 2/' /etc/nitro_enclaves/allocator.yaml
  sudo systemctl restart nitro-enclaves-allocator.service
  sudo sed -i -E 's/^( *memory_mib:).*/\1 9216/' /etc/nitro_enclaves/allocator.yaml
  sudo sed -i -E 's/^( *cpu_count:).*/\1 4/' /etc/nitro_enclaves/allocator.yaml
  sudo systemctl restart nitro-enclaves-allocator.service
  ```

* Enclave attestation and inference:  
  ```bash
  make append-pcr0
  make run-enclave
  sudo ss -lpnA vsock | grep -w ':7002'
  ```

* Party data operations:  
  ```bash
  make party-download
  make party-verify
  make party-rewrap
  make party-collect
  ```
## Blockchain and IPFS anchoring
The above will deploy the whole project while skipping blockchain and IPFS pinning. To setup anchoring:
- log into the ec2 instance and move to the directory /home/ubuntu/analysis/fed-analysis-keys
- Rename the `.env.example` to `.env` then update the below keys:
```
PRIVATE_KEY="<YOUR_BLOCKCHAIN_PRIVATE_KEY>"   # with test POL balance because smart contract is deployed on Polygon Amoy
RPC_URL="https://rpc-amoy.polygon.technology"
PINATA_JWT_UPLOAD="<YOUR_PINATA_JWT>"         # with write priviledges
```
- Rerun the above make commands from the directory `/home/ubuntu/analysis` in the server.