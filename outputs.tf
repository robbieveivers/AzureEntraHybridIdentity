output "bastion_public_ip" {
  value       = var.bastion != null ? module.bastion[0].public_ip : null
  description = "Value of the Bastion Public IP, Use this to remote into hosts safely"
}
output "ansible_public_ip" {
  value       = module.ansiblecontroller.public_ip
  description = "Value of the Ansible Controller Public IP, Use this to remote into hosts safely"
}