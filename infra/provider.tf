terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "=4.41.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "2.6.1"
    }
    msgraph = {
      source = "microsoft/msgraph"
      version = "0.2.0"
    }
  }
  backend "local" {

  }
}
provider "azurerm" {
  features {
    key_vault {
      purge_soft_deleted_secrets_on_destroy = true
    }
  }
}
