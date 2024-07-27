#Attach our subnet here
resource "azurerm_resource_group" "rg" {
  name     = "rg-${var.resource_group_name}"
  location = var.location
}

resource "azurerm_network_interface" "nic" {
  name                = "${var.vm_name}-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "tls_private_key" "ansible_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096

  lifecycle {
    create_before_destroy = false
  }
}

resource "azurerm_ssh_public_key" "ansible_ssh" {
  name                = "${var.vm_name}-ssh-key"
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  public_key          = tls_private_key.ansible_ssh.public_key_openssh
}

resource "azurerm_key_vault_secret" "ansible_ssh" {
  name         = "${var.vm_name}-private-key"
  value        = tls_private_key.ansible_ssh.private_key_pem
  key_vault_id = var.key_vault_id
}

resource "azurerm_linux_virtual_machine" "controller" {
  name                  = "${var.vm_name}-ansible-controller"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = var.location
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.nic.id]
  tags                  = var.tags

  #TODO: Add key to KV storage
  admin_ssh_key {
    username   = var.admin_username
    public_key = tls_private_key.ansible_ssh.public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

resource "azurerm_virtual_machine_extension" "ansible_install" {
  name                 = "installansible"
  virtual_machine_id   = azurerm_linux_virtual_machine.controller.id
  publisher            = "Microsoft.Azure.Extensions"
  type                 = "CustomScript"
  type_handler_version = "2.0"

  settings = <<SETTINGS
    {
        "commandToExecute": "sudo apt-get update -y && sudo apt-get install -y software-properties-common && sudo apt-add-repository --yes --update ppa:ansible/ansible && sudo apt-get install -y ansible"
    }
  SETTINGS
}