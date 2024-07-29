resource "azurerm_resource_group" "rg" {
  name     = "rg-${var.vnet_name}"
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "vnet" {
  name                = var.vnet_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  address_space       = var.address_space
  tags                = var.tags
}

resource "azurerm_subnet" "subnet" {

  for_each = var.subnets

  name                 = each.key
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = each.value.address_prefixes
}

resource "azurerm_network_security_group" "nsg" {
  for_each = { for k, v in var.subnets : k => v if v.nsg != null }

  name                = each.value.nsg.name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_network_security_rule" "nsg_rule" {
  for_each = { for idx, rule in local.flattened_rules : "${rule.subnet_key}-${rule.rule.name}" => rule }

  name                        = each.value.rule.name
  priority                    = each.value.rule.priority
  direction                   = each.value.rule.direction
  access                      = each.value.rule.access
  protocol                    = each.value.rule.protocol
  source_port_range           = each.value.rule.source_port_range
  destination_port_range      = each.value.rule.destination_port_range
  source_address_prefix       = each.value.rule.source_address_prefix
  destination_address_prefix  = each.value.rule.destination_address_prefix
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg[each.value.subnet_key].name
}

resource "azurerm_subnet_network_security_group_association" "subnet_nsg_assoc" {
  for_each = { for k, v in var.subnets : k => v if v.nsg != null }

  subnet_id                 = azurerm_subnet.subnet[each.key].id
  network_security_group_id = azurerm_network_security_group.nsg[each.key].id
}