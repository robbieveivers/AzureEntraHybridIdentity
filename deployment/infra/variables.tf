variable "location" {
  description = "The location/region where the virtual network will be created."
  type        = string
}

variable "tags" {
  description = "A mapping of tags to assign to the resource."
  type        = map(string)
}

variable "virtual_network" {
  description = "Virtual Network Block"
  type = object({
    name          = string
    address_space = list(string)
    subnets = map(object({
      address_prefixes = list(string)
      nsg = optional(object({
        name = string
        rules = list(object({
          name                       = string
          priority                   = number
          direction                  = string
          access                     = string
          protocol                   = string
          source_port_range          = string
          destination_port_range     = string
          source_address_prefix      = string
          destination_address_prefix = string
        }))
      }))
    }))
  })
}

variable "ansible_controller" {
  description = "Ansible Controller Block"
  type = object({
    vm_name           = string
    vm_size           = string
    admin_username    = string
    subnet_name       = string
    require_public_ip = bool
  })
}

variable "bastion" {
  description = "Bastion Block"
  type = object({
    bastion_name = string
    subnet_name  = string
  })
  default = null
}

variable "keyvault_name" {
  description = "The name of the Key Vault"
  type        = string
}

variable "win_virtual_machines" {
  description = "Windows Virtual Machines Block"
  type = map(object({
    vm_size        = string
    admin_username = string
    admin_password = string
    subnet_name    = string
  }))

}