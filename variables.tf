variable "location" {
  description = "The Azure region to deploy resources in."
  type        = string
  
  validation {
    condition     = can(regex("^[a-z]+$", replace(var.location, "/[a-z]/", "")))
    error_message = "The location must be a valid Azure region name (e.g., 'eastus', 'westeurope')."
  }
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
    
    validation {
      condition     = length(var.ad_password) >= 12
      error_message = "The password must be at least 12 characters long for security."
    }
}

variable "subscription_id" {
  description = "The Azure Subscription ID to use."
  type        = string
  
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.subscription_id))
    error_message = "The subscription_id must be a valid UUID format."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "AzureEntraHybridIdentity"
    ManagedBy   = "Terraform"
    Environment = "Testing"
  }
}
