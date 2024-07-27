module "vnet" {
  source              = "./vnet"
  vnet_name           = var.virtual_network.name
  resource_group_name = var.virtual_network.name
  location            = var.location
  address_space       = var.virtual_network.address_space
  subnets             = var.virtual_network.subnets
  tags                = var.tags
}