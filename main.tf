module "vnet" {
  source              = "./vnet"
  vnet_name           = var.virtual_network.name
  resource_group_name = var.virtual_network.name
  location            = var.location
  address_space       = var.virtual_network.address_space
  subnets             = var.virtual_network.subnets
  tags                = var.tags
}

module "ansiblecontroller" {
  source              = "./ansiblecontroller"
  vm_name             = var.ansible_controller.vm_name
  resource_group_name = var.ansible_controller.vm_name
  location            = var.location
  vm_size             = var.ansible_controller.vm_size
  admin_username      = var.ansible_controller.admin_username
  subnet_id           = module.vnet.subnet_ids[var.ansible_controller.subnet_name]
  key_vault_id        = module.keyvault.id
  tags                = var.tags
}

module "bastion" {
  source       = "./bastion"
  bastion_name = var.bastion.bastion_name
  location     = var.location
  subnet_id    = module.vnet.subnet_ids[var.bastion.subnet_name]
  tags         = var.tags
}

module "keyvault" {
  source        = "./keyvault"
  keyvault_name = var.keyvault_name
  location      = var.location
  tags          = var.tags
}