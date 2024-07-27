variable "vnet_name" {
  description = "The name of the virtual network."
  type        = string
}

variable "resource_group_name" {
  description = "The name of the resource group in which to create the virtual network."
  type        = string
}

variable "location" {
  description = "The location/region where the virtual network will be created."
  type        = string
}

variable "address_space" {
  description = "The address space that is used the virtual network."
  type        = list(string)
}

variable "tags" {
  description = "A mapping of tags to assign to the resource."
  type        = map(string)
}

variable "subnets" {
  description = "A map of subnets to create within the virtual network."
  type = map(object({
    address_prefixes = list(string)
  }))

}