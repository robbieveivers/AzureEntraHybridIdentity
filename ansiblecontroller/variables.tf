variable "vm_name" {
  description = "The name of the Linux virtual machine."
  type        = string
}

variable "resource_group_name" {
  description = "The name of the resource group."
  type        = string
}

variable "location" {
  description = "The location/region where the VM will be created."
  type        = string
}

variable "vm_size" {
  description = "The size of the Linux virtual machine."
  type        = string
}

variable "admin_username" {
  description = "The admin username for the Linux VM."
  type        = string
}

variable "tags" {
  description = "A mapping of tags to assign to the resource."
  type        = map(string)
}

variable "subnet_id" {
  description = "The ID of the subnet to deploy the VM in."
  type        = string
}