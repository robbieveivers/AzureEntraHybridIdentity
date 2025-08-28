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
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 1.19"
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

# Get Azure CLI access token for Microsoft Graph
data "external" "az_graph_token" {
  program = ["bash", "-c", "az account get-access-token --resource https://graph.microsoft.com --query '{access_token: accessToken}' -o json"]
}

# Configure REST API provider for Microsoft Graph
provider "restapi" {
  uri                  = "https://graph.microsoft.com"
  write_returns_object = true
  
  headers = {
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer ${data.external.az_graph_token.result.access_token}"
  }
}