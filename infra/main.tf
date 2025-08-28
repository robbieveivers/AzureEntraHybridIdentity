# User-assigned managed identity for VM and Key Vault
resource "azurerm_user_assigned_identity" "vm_identity" {
  name                = "b2atsv2-user-assigned-identity"
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name
}
locals {
  location = "australiasoutheast"
  offline_token_value = azurerm_key_vault_secret.offline_token.value
}

data "http" "myip" {
  url = "https://api.ipify.org/"
}

resource "azurerm_resource_group" "rg" {
  name     = "b2atsv2-win2025-rg"
  location = local.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "b2atsv2-vnet"
  address_space       = ["10.10.0.0/16"]
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azapi_resource" "bastion_dev" {
  # AZ Api is required because Bastion host in azurerm is not supported for Developer SKU
  type      = "Microsoft.Network/bastionHosts@2023-09-01"
  name      = "b2atsv2-bastion-dev"
  location  = local.location
  parent_id = azurerm_resource_group.rg.id
  body = {
    properties = {
      virtualNetwork = {
        id = azurerm_virtual_network.vnet.id
      }
    }
    sku = {
      name = "Developer"
    }
  }
}

resource "azurerm_subnet" "subnet" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.10.1.0/24"]
  service_endpoints    = ["Microsoft.KeyVault"]
}

resource "azurerm_public_ip" "pip" {
  name                = "b2atsv2-win2025-pip"
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
  sku                 = "Basic"
}

resource "azurerm_network_interface" "nic" {
  name                = "b2atsv2-win2025-nic"
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_network_security_group" "nsg" {
  name                = "b2atsv2-win2025-nsg"
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "Allow-RDP"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = chomp(data.http.myip.response_body)
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-SSH"
    priority                   = 1004
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = chomp(data.http.myip.response_body)
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface_security_group_association" "nic_nsg" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# Minimal Azure Key Vault setup
resource "azurerm_key_vault" "kv" {
  name                      = "b2atsv3-kv"
  location                  = local.location
  resource_group_name       = azurerm_resource_group.rg.name
  tenant_id                 = data.azurerm_client_config.current.tenant_id
  sku_name                  = "standard"
  purge_protection_enabled  = false
  enable_rbac_authorization = false

  access_policy {
    tenant_id          = data.azurerm_client_config.current.tenant_id
    object_id          = azurerm_user_assigned_identity.vm_identity.principal_id
    secret_permissions = ["Get", "List"]
  }

  access_policy {
    tenant_id          = data.azurerm_client_config.current.tenant_id
    object_id          = data.azurerm_client_config.current.object_id
    secret_permissions = ["Get", "List", "Set", "Delete"]
  }

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = [chomp(data.http.myip.response_body)]
    virtual_network_subnet_ids = [azurerm_subnet.subnet.id]
  }
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault_secret" "admin_password" {
  name         = "vm-admin-password"
  value        = "P@ssword1234!"
  key_vault_id = azurerm_key_vault.kv.id
}

#Tracking when could this be Ephemral resources, Lets replace with somethinglese
data "external" "connectorjwttoken" {
  program = ["bash", "${path.module}/get-token.sh"]
}

# resource "terraform_data" "ansible_provision" {
#   triggers_replace = {
#     playbook = filesha256("${path.module}/create_dir.yml")
#   }

#   provisioner "local-exec" {
#     command = "OFFLINE_TOKEN=$(bash ${path.module}/get-token.sh) ansible-playbook ... --extra-vars \"offline_token=$OFFLINE_TOKEN\""
#   }
# }

resource "azurerm_key_vault_secret" "offline_token" {
  name = "offline-install-token"
  value = "test"
  key_vault_id = azurerm_key_vault.kv.id
}

# ephemeral "random_password" "password" {
#   length           = 16
#   special          = true
#   override_special = "!#$%&*()-_=+[]{}<>:?"
# }

# resource "azurerm_key_vault_secret" "example" {
#   name             = "vm-password"
#   value_wo         = ephemeral.random_password.password.result
#   value_wo_version = 1
#   key_vault_id     = azurerm_key_vault.kv.id
# }

resource "azurerm_windows_virtual_machine" "vm" {
  name                = "b2atsv4-win25"
  resource_group_name = azurerm_resource_group.rg.name
  location            = local.location
  size                = "Standard_B2s_v2"
  admin_username      = "azureuser"
  admin_password      = azurerm_key_vault_secret.admin_password.value
  patch_mode = "AutomaticByPlatform"
  network_interface_ids = [
    azurerm_network_interface.nic.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    name                 = "b2atsv2-win2025-osdisk"
    disk_size_gb         = 64
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-azure-edition-smalldisk"
    version   = "latest"
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vm_identity.id]
  }
}

# Ansible provisioner with triggers and depends_on
resource "terraform_data" "ansible_provision" {
  triggers_replace = {
    # Place the vars for the playbook here. 
    playbook = filesha256("${path.module}/create_dir.yml")
  }

provisioner "local-exec" {
  environment = {
   #ANSIBLE_PASSWORD = azurerm_key_vault_secret.admin_password.value
    OFFLINE_TOKEN = "${data.external.connectorjwttoken.result.access_token}" #data.external.connectorjwttoken.result.access_token
  }
  command = "ansible-playbook -i '${azurerm_public_ip.pip.ip_address},' -u azureuser -v --extra-vars \"{\\\"ansible_user\\\":\\\"azureuser\\\",\\\"ansible_password\\\":\\\"P@ssword1234!\\\",\\\"ansible_ssh_common_args\\\":\\\"-o StrictHostKeyChecking=no\\\",\\\"ansible_shell_type\\\":\\\"cmd\\\",\\\"offline_token\\\":\\\"$OFFLINE_TOKEN\\\"}\" --connection=ssh ${path.module}/create_dir.yml"
}

  depends_on = [azurerm_windows_virtual_machine.vm]
}

