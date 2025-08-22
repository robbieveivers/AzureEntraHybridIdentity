variable "vm_name" {
  description = "The name of the Windows virtual machine."
  type        = string
}

variable "location" {
  description = "The location/region where the VM will be created."
  type        = string
}

variable "vm_size" {
  description = "The size of the Windows virtual machine."
  type        = string
}

variable "admin_username" {
  description = "The admin username for the Windows VM."
  type        = string
}

variable "admin_password" {
  description = "The admin password for the Windows VM."
  type        = string
  sensitive   = true
}

variable "subnet_id" {
  description = "The ID of the subnet to deploy the VM in."
  type        = string
}

variable "tags" {
  description = "A mapping of tags to assign to the resource."
  type        = map(string)
}