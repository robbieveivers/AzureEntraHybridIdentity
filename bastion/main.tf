resource "azurerm_resource_group" "rg" {
  name     = "rg-bastion"
  location = var.location
  tags     = var.tags
}

resource "azurerm_public_ip" "bastion" {
  name                = "bastion-public-ip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_bastion_host" "bastion" {
  name                = var.bastion_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location

  ip_configuration {
    name                 = "configuration"
    subnet_id            = var.subnet_id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }
}