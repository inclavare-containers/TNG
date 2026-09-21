output "ecs_eip" {
  description = "Public IP of the ECS (TNG egress + echo), from the instance's own bandwidth. SSH + the OHTTP port (demo)."
  value       = alicloud_instance.ecs.public_ip
}

output "ssh_key_path" {
  description = "Local path to the generated SSH private key (gitignored) for the one-shot tshark capture on the ECS."
  value       = abspath(local_file.ssh_key.filename)
}

output "ecs_instance_id" {
  value = alicloud_instance.ecs.id
}

output "fc_function_name" {
  value = alicloud_fcv3_function.relay.function_name
}

output "fc_egress_ip" {
  description = "FC relay's FIXED public egress IP (via NAT gateway + EIP). The ECS SG :8443 is narrowed to this IP."
  value       = alicloud_eip.fc_egress.ip_address
}

output "fc_trigger_url" {
  description = "FC 3.0 HTTP trigger internet URL (fcapp.run)."
  value       = alicloud_fcv3_trigger.relay.http_trigger[0].url_internet
}
