# provider "azuread" {
#   # Configuration is optional if using the same credentials as azurerm
# }

# resource "azurerm_user_assigned_identity" "hybrid_identity" {
#   name                = "hybrid-identity-mi1"
#   resource_group_name = azurerm_resource_group.rg.name
#   location            = azurerm_resource_group.rg.location
# }

# # Assign "Hybrid Identity Administrator" role to the managed identity at the tenant root scope
# resource "azuread_directory_role" "hybrid_identity_admin" {
#   display_name = "Hybrid Identity Administrator"
# }

# resource "azuread_directory_role_assignment" "hybrid_identity_admin_assignment" {
#   role_id             = azuread_directory_role.hybrid_identity_admin.template_id
#   principal_object_id = azurerm_user_assigned_identity.hybrid_identity.principal_id
# }

# output "hybrid_identity_managed_identity_id" {
#   value = azurerm_user_assigned_identity.hybrid_identity.id
# }
