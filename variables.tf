variable "virtual_network" {
  description = "Virtual Network Block"
  type = object({
    name          = string
    address_space = list(string)
    subnets = map(object({
      address_prefixes = list(string)
    }))
  })
}

variable "location" {
  description = "The location/region where the virtual network will be created."
  type        = string
}

variable "tags" {
  description = "A mapping of tags to assign to the resource."
  type        = map(string)
}