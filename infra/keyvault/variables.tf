variable "keyvault_name" {
  description = "The name of the Key Vault"
  type        = string
}

variable "location" {
  description = "The location of the Key Vault"
  type        = string
}

variable "tags" {
  description = "A mapping of tags to assign to the resource."
  type        = map(string)

}
