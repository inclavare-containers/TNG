# All demo resources are overridable variables. Defaults target cn-beijing +
# an Alibaba Cloud Linux 3 image on a g8i (Intel TDX-capable) instance.
#
# NOTE: TDX is NOT enabled here. The alicloud Terraform provider does not yet
# support the "confidential VM" flag; the instance is created as a normal g8i.
# The demo runs RA-off, so TDX is not required for the anonymization proof.
# When TDX-via-Terraform lands, enable it here and flip RA on.

variable "region" {
  description = "Aliyun region."
  type        = string
  default     = "cn-beijing"
}

variable "ssh_allow_cidr" {
  description = "CIDR allowed to reach the ECS SSH port. run-demo.sh narrows this to the demo runner's own /32 before apply. Must be <= /24; never 0.0.0.0/0."
  type        = string
}

variable "availability_zone" {
  description = "Availability zone that offers the chosen instance type (g8i/TDX: cn-beijing-i is a confidential-capable zone)."
  type        = string
  default     = "cn-beijing-i"
}

variable "instance_type" {
  description = "ECS instance type (g8i is Intel TDX-capable)."
  type        = string
  default     = "ecs.g8i.4xlarge"
}

variable "image_family" {
  description = "ECS image family (Alibaba Cloud Linux 3 x64 LTS by default)."
  type        = string
  default     = "acs:alibaba_cloud_linux_3_2104_lts_x64"
}

variable "system_disk_size" {
  description = "ECS system disk size in GB."
  type        = number
  default     = 60
}

variable "tng_rpm_repo_url" {
  description = "Optional baseurl for a TNG RPM repo (if trusted-network-gateway is not in the image's default repos). Leave empty to rely on the default repos."
  type        = string
  default     = ""
}

variable "fc_memory_size" {
  description = "FC relay function memory in MB."
  type        = number
  default     = 512
}

variable "fc_timeout" {
  description = "FC relay function timeout in seconds."
  type        = number
  default     = 30
}

variable "fc_log_request_body" {
  description = "When true, the FC relay logs the tunnel request body (ciphertext) to FC logs. Default off (production); the demo script sets it to true via TF_VAR_fc_log_request_body."
  type        = string
  default     = "false"
}
