output "subnet_ids" {
  value = { for k, v in azurerm_subnet.subnet : k => v.id }
}