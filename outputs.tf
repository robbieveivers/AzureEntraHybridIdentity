output "bastion_public_ip" {
  value = module.bastion.public_ip
  description = "Value of the Bastion Public IP, Use this to remote into hosts safely"
}