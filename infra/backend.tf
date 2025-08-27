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
    ansible = {
      source  = "ansible/ansible"
      version = "1.3.0"
    }
    msgraph = {
      source = "microsoft/msgraph"
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
  subscription_id = "f5f39478-783a-4639-a51c-b5c278fbb33c"

}