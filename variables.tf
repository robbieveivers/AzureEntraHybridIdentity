variable "location" {
  description = "The Azure region to deploy resources in."
  type        = string
}

variable "ad_name" {
  description = "The name of the Active Directory domain."
  type        = string
  default     = "contoso.local"
}

variable "ad_netbios_name" {
    description = "The NetBIOS name of the Active Directory domain."
    type        = string
    default     = "CONTOSO"
}

variable "ad_username" {
    description = "The ad admin username for the Windows VM."
    type        = string
    default     = "azureuser"
}

variable "ad_password" {
    description = "The ad admin password for the Windows VM."
    type        = string
    sensitive   = true
}

variable "subscription_id" {
  description = "The Azure Subscription ID to use."
  type        = string
}
