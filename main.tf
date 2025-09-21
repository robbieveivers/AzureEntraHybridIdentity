data "azurerm_client_config" "current" {}

#using the object id lets grab the UPN of the user
data "azuread_user" "upn_for_hybrid_identity_token_user" {
  object_id = data.azurerm_client_config.current.object_id
}

data "http" "myip" {
  url = "https://api.ipify.org/"
}

resource "azurerm_resource_group" "rg" {
  name     = "win2025-rg"
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "vnet"
  address_space       = ["10.10.0.0/16"]
  location            = var.location
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
  name                = "win2025-pip"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Basic"
}

resource "azapi_resource" "bastion_dev" {
  # AZ Api is required because Bastion host in azurerm does not support Developer SKU
  type      = "Microsoft.Network/bastionHosts@2023-09-01"
  name      = "bastion-dev"
  location  = var.location
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
    depends_on = [terraform_data.ansible_provision_cloud_agent]
}


resource "azurerm_network_interface" "nic" {
  name                = "win2025-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_network_security_group" "nsg" {
  name                = "win2025-nsg"
  location            = var.location
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
  security_rule {
    name                       = "Allow-Winrm-Http"
    priority                   = 1005
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5985"
    source_address_prefix      = chomp(data.http.myip.response_body)
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface_security_group_association" "nic_nsg" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

#Tracking when could this be Ephemeral resource
#https://github.com/hashicorp/terraform-provider-external/pull/442/commits/b03d94cd9287821be26b60d7aa9b41813e72ae93#diff-58d6a027753b50994deb7e11e4a99dde423f35844986019bd9cea5e0c94aba22
data "external" "connectorjwttoken" {
  program = ["bash", "${path.module}/get-token.sh"]
}

resource "azurerm_windows_virtual_machine" "vm" {
  name                = "domain-win25"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  size                = "Standard_B2as_v2"
  admin_username      = var.ad_username
  admin_password      = var.ad_password
  # patch_mode          = "AutomaticByPlatform"
  network_interface_ids = [
    azurerm_network_interface.nic.id
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    name                 = "win2025-osdisk"
    disk_size_gb         = 64
  }

  #Should use HTTPS, I tried using SSH the AD ansible didnt work well with ssh.
  winrm_listener {
      protocol = "Http"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-smalldisk-g2"
    version   = "latest"
  }
  depends_on = [ azurerm_network_interface_security_group_association.nic_nsg ]
}

# Ansible provisioner with triggers and depends_on
resource "terraform_data" "ansible_provision_cloud_agent" {
  triggers_replace = {
    # Place the vars for the playbook here. 
    playbook = filesha256("${path.module}/ad_enroll_agent.yml")
  }

provisioner "local-exec" {
  environment = {
    # ANSIBLE_PASSWORD = azurerm_key_vault_secret.admin_password.value
    OFFLINE_TOKEN = "${data.external.connectorjwttoken.result.access_token}"
  }
  ##Need to add in a bunch for variables here
  command = <<-EOT
    ansible-playbook -i '${azurerm_public_ip.pip.ip_address},' -vvv \
      --extra-vars '{
        "ansible_user": "azureuser",
        "ansible_password": "P@ssw0rd!23456",
        "ansible_connection": "winrm",
        "ansible_winrm_transport": "ntlm",
        "ansible_winrm_server_cert_validation": "ignore",
        "ansible_port": 5985,
        "offline_token": "${data.external.connectorjwttoken.result.access_token}",
        "offline_token_upn": "${data.azuread_user.upn_for_hybrid_identity_token_user.user_principal_name}",
        "ad_domain_name" : "${var.ad_name}",
        "ad_netbios_name" : "${var.ad_netbios_name}",
        "tenant_id" : "${data.azurerm_client_config.current.tenant_id}",
        "subscription_id" : "${data.azurerm_client_config.current.subscription_id}"
      }' \
      ${path.module}/ad_enroll_agent.yml
  EOT
}
  depends_on = [azurerm_windows_virtual_machine.vm]
}

module "entra-cloud-sync-config" {
  source  = "IdentityUnoffical/entra-cloud-sync-config/msgraph"
  version = "0.0.3"
  ad_domain = var.ad_name
  tenant_id = data.azurerm_client_config.current.tenant_id
  depends_on = [ terraform_data.ansible_provision_cloud_agent ]
}
