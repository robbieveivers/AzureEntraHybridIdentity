variable "location" {
  description = "The location/region where the virtual network will be created."
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

variable "bastion_name" {
  description = "The name of the Bastion Host."
  type        = string

}