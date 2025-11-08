output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.rg.name
}

output "vm_name" {
  description = "Name of the Windows virtual machine"
  value       = azurerm_windows_virtual_machine.vm.name
}

output "vm_public_ip" {
  description = "Public IP address of the virtual machine"
  value       = azurerm_public_ip.pip.ip_address
}

output "vm_private_ip" {
  description = "Private IP address of the virtual machine"
  value       = azurerm_network_interface.nic.private_ip_address
}

output "ad_domain_name" {
  description = "Active Directory domain name"
  value       = var.ad_name
}

output "bastion_dns_name" {
  description = "DNS name of the Azure Bastion host"
  value       = azapi_resource.bastion_dev.name
}

output "admin_username" {
  description = "Administrator username for the VM"
  value       = var.ad_username
  sensitive   = false
}

output "connection_instructions" {
  description = "Instructions for connecting to the VM"
  value       = <<-EOT
    Connect to the VM using one of these methods:
    
    1. Azure Bastion (recommended):
       - Navigate to the VM in Azure Portal
       - Click 'Connect' > 'Bastion'
       - Use credentials: ${var.ad_username}@${var.ad_name}
    
    2. RDP (if enabled):
       - IP: ${azurerm_public_ip.pip.ip_address}
       - Port: 3389
       - Username: ${var.ad_username}@${var.ad_name}
  EOT
}
