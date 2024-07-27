
resource "azurerm_resource_group" "rg" {
  name     = "rg-${var.keyvault_name}"
  location = var.location
  tags     = var.tags
}


resource "azurerm_key_vault" "keyvault" {
  name                     = var.keyvault_name
  location                 = var.location
  resource_group_name      = azurerm_resource_group.rg.name
  tenant_id                = data.azurerm_client_config.current.tenant_id
  sku_name                 = "standard"
  purge_protection_enabled = false
  tags                     = var.tags

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Recover",
      "Backup",
      "Restore",
      "Purge",
    ]
  }
}