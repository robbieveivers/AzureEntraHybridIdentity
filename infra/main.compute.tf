# User-assigned managed identity for VM and Key Vault
resource "azurerm_user_assigned_identity" "vm_identity" {
  name                = "b2atsv2-user-assigned-identity"
  location            = local.location
  resource_group_name = azurerm_resource_group.rg.name
}
locals {
  location = "australiasoutheast"
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
  allocation_method   = "Static"
  sku                 = "Basic"
}

resource "azapi_resource" "bastion_dev" {
  # AZ Api is required because Bastion host in azurerm does not support Developer SKU
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
    depends_on = [azurerm_public_ip.pip]
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

# # Minimal Azure Key Vault setup
# resource "azurerm_key_vault" "kv" {
#   name                      = "b2atsv4-kv"
#   location                  = local.location
#   resource_group_name       = azurerm_resource_group.rg.name
#   tenant_id                 = data.azurerm_client_config.current.tenant_id
#   sku_name                  = "standard"
#   purge_protection_enabled  = false
#   enable_rbac_authorization = true
# }

# resource "random_password" "admin" {
#   length           = 20
#   special          = true
#   override_special = "!#$%&*()-_=+[]{}<>:?"
# }

# resource "azurerm_key_vault_secret" "admin_password" {
#   name         = "vm-admin-password2"
#   value        = "P@ssw0rd!23456" # Use random_password.admin.result for production
#   key_vault_id = azurerm_key_vault.kv.id
# }

#Tracking when could this be Ephemeral resource
#https://github.com/hashicorp/terraform-provider-external/pull/442/commits/b03d94cd9287821be26b60d7aa9b41813e72ae93#diff-58d6a027753b50994deb7e11e4a99dde423f35844986019bd9cea5e0c94aba22
data "external" "connectorjwttoken" {
  program = ["bash", "${path.module}/get-token.sh"]
}

resource "azurerm_windows_virtual_machine" "vm" {
  name                = "b2atsv4-win25"
  resource_group_name = azurerm_resource_group.rg.name
  location            = local.location
  size                = "Standard_B4as_v2"
  admin_username      = "azureuser"
  admin_password      = "P@ssw0rd!23456"
  network_interface_ids = [
    azurerm_network_interface.nic.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    name                 = "b2atsv2-win2025-osdisk"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-g2"
    version   = "latest"
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vm_identity.id]
  }
  depends_on = [ azurerm_network_interface_security_group_association.nic_nsg ]
}

# Ansible provisioner with triggers and depends_on
resource "terraform_data" "ansible_provision" {
  triggers_replace = {
    # Place the vars for the playbook here. 
    playbook = filesha256("${path.module}/create_dir.yml")
  }

provisioner "local-exec" {
  environment = {
    # ANSIBLE_PASSWORD = azurerm_key_vault_secret.admin_password.value
    OFFLINE_TOKEN = "${data.external.connectorjwttoken.result.access_token}" #data.external.connectorjwttoken.result.access_token
  }
  command = "ansible-playbook -i '${azurerm_public_ip.pip.ip_address},' -u azureuser -vv --extra-vars \"{\\\"ansible_user\\\":\\\"azureuser\\\",\\\"ansible_password\\\":\\\"P@ssw0rd!23456\\\",\\\"ansible_ssh_common_args\\\":\\\"-o StrictHostKeyChecking=no\\\",\\\"ansible_shell_type\\\":\\\"cmd\\\",\\\"offline_token\\\":\\\"$OFFLINE_TOKEN\\\"}\" --connection=ssh ${path.module}/create_dir.yml"
}
  depends_on = [azurerm_windows_virtual_machine.vm]
}

