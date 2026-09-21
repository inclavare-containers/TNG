terraform {
  required_version = ">= 1.4"
  required_providers {
    # TDX needs the security_options block, which only the
    # inclavare-containers/terraform-provider-alicloud fork (feat/ecs-security-options)
    # has until upstream merges it. run-demo.sh clones + builds that fork into a
    # sibling dir and points Terraform at it via dev_overrides. The version is a
    # floor only (dev_overrides ignores it).
    alicloud = { source = "aliyun/alicloud", version = ">= 1.293.0" }
    archive  = { source = "hashicorp/archive", version = "~> 2.4" }
    # The demo SSHes into the ECS to run a one-shot tshark capture on the
    # relay->egress leg (Leg B). Terraform generates the keypair itself and
    # writes the private key to a gitignored local file; no external key pair
    # is required.
    tls   = { source = "hashicorp/tls", version = "~> 4.0" }
    local = { source = "hashicorp/local", version = "~> 2.4" }
  }
}

provider "alicloud" {}

# SSH keypair generated in-place: the public key is registered with Aliyun, the
# private key is written to build/tng-demo-key (gitignored). run-demo.sh reads
# the path from the ssh_key_path output.
resource "tls_private_key" "demo" {
  algorithm = "ED25519"
}

resource "alicloud_key_pair" "demo" {
  key_name   = "tng-ohttp-relay-demo"
  public_key = tls_private_key.demo.public_key_openssh
}

resource "local_file" "ssh_key" {
  filename        = "${path.module}/build/tng-demo-key"
  content         = tls_private_key.demo.private_key_openssh
  file_permission = "0600"
}

# Select an Alibaba Cloud Linux 3 image (system image, x64 LTS family).
data "alicloud_images" "alinux3" {
  owners       = "system"
  image_family = var.image_family
  most_recent  = true
}

# Zip the FC relay function (built-in nodejs20 runtime, index.js handler).
data "archive_file" "relay" {
  type        = "zip"
  source_dir  = "${path.module}/../fc-relay"
  output_path = "${path.module}/build/relay.zip"
}

resource "alicloud_vpc" "vpc" {
  name       = "tng-ohttp-relay-demo"
  cidr_block = "10.0.0.0/16"
}

resource "alicloud_vswitch" "vswitch" {
  name              = "tng-ohttp-relay-demo"
  vpc_id            = alicloud_vpc.vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = var.availability_zone
}

resource "alicloud_security_group" "sg" {
  name   = "tng-ohttp-relay-demo"
  vpc_id = alicloud_vpc.vpc.id
}

# SSH for the demo's one-shot tshark capture on the relay->egress leg. Narrowed
# to the demo runner's /32 (run-demo.sh sets var.ssh_allow_cidr before apply);
# never 0.0.0.0/0.
resource "alicloud_security_group_rule" "ssh" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = alicloud_security_group.sg.id
  cidr_ip           = var.ssh_allow_cidr
}

# Port 80 for the ACME HTTP challenge (acme.sh standalone issues the LE cert).
resource "alicloud_security_group_rule" "acme" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "80/80"
  security_group_id = alicloud_security_group.sg.id
  cidr_ip           = "0.0.0.0/0"
}

# --- FC fixed egress IP (NAT gateway + EIP + SNAT) -----------------------
# FC function binds to the VPC + uses this NAT gateway for a FIXED public
# egress IP. This avoids Aliyun's auto-restriction on 0.0.0.0/0 SG rules:
# the ECS SG :8443 is narrowed to this EIP's /32 at apply time.
resource "alicloud_vswitch" "fc_vswitch" {
  name              = "tng-ohttp-relay-demo-fc"
  vpc_id            = alicloud_vpc.vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = var.availability_zone
}

resource "alicloud_eip" "fc_egress" {
  address_name         = "tng-fc-egress"
  bandwidth            = "5"
  internet_charge_type = "PayByTraffic"
}

resource "alicloud_nat_gateway" "nat" {
  vpc_id       = alicloud_vpc.vpc.id
  vswitch_id   = alicloud_vswitch.fc_vswitch.id
  name         = "tng-fc-nat"
  nat_type     = "Enhanced"
  payment_type = "PayAsYouGo"
}

resource "alicloud_eip_association" "eip_nat" {
  allocation_id = alicloud_eip.fc_egress.id
  instance_id   = alicloud_nat_gateway.nat.id
}

resource "alicloud_snat_entry" "snat" {
  snat_table_id     = alicloud_nat_gateway.nat.snat_table_ids
  source_vswitch_id = alicloud_vswitch.fc_vswitch.id
  snat_ip           = alicloud_eip.fc_egress.ip_address
}

resource "alicloud_security_group" "fc_sg" {
  name   = "tng-ohttp-relay-demo-fc"
  vpc_id = alicloud_vpc.vpc.id
}

# TLS relay->egress (nginx terminates TLS on :8443, proxies to localhost:9000).
# :9000 is NOT public. SG narrowed to FC's FIXED egress EIP (no auto-restriction).
resource "alicloud_security_group_rule" "tls" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "8443/8443"
  security_group_id = alicloud_security_group.sg.id
  cidr_ip           = "${alicloud_eip.fc_egress.ip_address}/32"
}

resource "alicloud_instance" "ecs" {
  instance_name        = "tng-ohttp-relay-demo"
  instance_type        = var.instance_type
  image_id             = data.alicloud_images.alinux3.images[0].id
  vswitch_id           = alicloud_vswitch.vswitch.id
  security_groups      = [alicloud_security_group.sg.id]
  system_disk_category = "cloud_essd"
  system_disk_size     = var.system_disk_size
  # The instance gets its own public IP + outbound internet (for cloud-init's
  # yum install). A separate EIP cannot be associated on top of this
  # (EIP_CAN_NOT_ASSOCIATE_WITH_PUBLIC_IP), so the FC relay + SSH use this IP.
  internet_max_bandwidth_out = 10
  key_name                   = alicloud_key_pair.demo.key_name
  # cloud-init (Terraform template): install TNG (egress) + the echo backend,
  # start both as systemd units. Only ${tng_rpm_repo_url} / %{ if } are templated.
  user_data = templatefile("${path.module}/user-data.sh", { tng_rpm_repo_url = var.tng_rpm_repo_url })
  # TDX confidential VM via the provider fork's security_options block. RA is
  # off for v1 (no attest/verify); TDX is enabled so the instance is a real
  # confidential VM when you later flip RA on (builtin AS).
  security_options {
    confidential_computing_mode = "TDX"
  }
  tags = { Name = "tng-ohttp-relay-demo" }
}

# --- FC 3.0 relay function (Node.js custom runtime) ---------------------
# FC 3.0 (fcv3) is the current API and activates the fcapp.run trigger URL
# (FC 2.0 does not, which is why the account-id fcapp.run domain 404'd). The
# function is a blind forwarder (see ../fc-relay/index.js): it forwards OHTTP
# ciphertext to EGRESS_URL and never decrypts.
resource "alicloud_fcv3_function" "relay" {
  function_name = "tng-relay"
  # Built-in Node.js runtime: no custom_runtime_config.command needed (the fork
  # had a bug sending that field). index.js uses the FC HTTP handler signature.
  runtime         = "nodejs20"
  handler         = "index.handler"
  memory_size     = var.fc_memory_size
  timeout         = var.fc_timeout
  internet_access = false # use VPC NAT gateway for fixed egress IP
  vpc_config {
    vpc_id            = alicloud_vpc.vpc.id
    vswitch_ids       = [alicloud_vswitch.fc_vswitch.id]
    security_group_id = alicloud_security_group.fc_sg.id
  }
  environment_variables = {
    EGRESS_URL       = "https://${alicloud_instance.ecs.public_ip}:8443"
    LOG_REQUEST_BODY = var.fc_log_request_body
  }
  code {
    # fcv3 code.zip_file is sent as-is; the FC 3.0 API wants base64 content.
    zip_file = filebase64(data.archive_file.relay.output_path)
  }
}

resource "alicloud_fcv3_trigger" "relay" {
  function_name = alicloud_fcv3_function.relay.function_name
  trigger_type  = "http"
  trigger_name  = "tng-ohttp-relay-trigger"
  qualifier     = "LATEST"
  trigger_config = jsonencode({
    authType = "anonymous"
    methods  = ["GET", "POST"]
  })
}
