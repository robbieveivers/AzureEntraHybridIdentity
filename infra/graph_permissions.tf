# # Azure AD App Registration for Hybrid Identity
# resource "azuread_application" "hybrid_identity" {
#   display_name = "hybrid-identity-app"
#   owners       = []
#   required_resource_access {
#     resource_app_id = data.azuread_service_principal.microsoft_graph.client_id
#     resource_access {
#       id   = data.azuread_service_principal.microsoft_graph.app_role_ids["Application.ReadWrite.All"]
#       type = "Role"
#     }
#     resource_access {
#       id   = data.azuread_service_principal.microsoft_graph.app_role_ids["Directory.Read.All"]
#       type = "Role"
#     }
#     resource_access {
#       id   = data.azuread_service_principal.microsoft_graph.app_role_ids["Directory.ReadWrite.All"]
#       type = "Role"
#     }
#     resource_access {
#       id   = data.azuread_service_principal.microsoft_graph.app_role_ids["Domain.ReadWrite.All"]
#       type = "Role"
#     }
#     resource_access {
#       id   = data.azuread_service_principal.microsoft_graph.app_role_ids["OnPremDirectorySynchronization.ReadWrite.All"]
#       type = "Role"
#     }
#     resource_access {
#       id   = data.azuread_service_principal.microsoft_graph.app_role_ids["Organization.ReadWrite.All"]
#       type = "Role"
#     }
#   }
# }

# # Service principal for the app registration
# resource "azuread_service_principal" "hybrid_identity" {
#   client_id = azuread_application.hybrid_identity.client_id
# }

# # Assign Microsoft Graph app roles to the app registration's service principal
# resource "azuread_app_role_assignment" "hybrid_identity_app_graph_application_readwrite" {
#   principal_object_id = azuread_service_principal.hybrid_identity.object_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Application.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_app_graph_directory_read" {
#   principal_object_id = azuread_service_principal.hybrid_identity.object_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Directory.Read.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_app_graph_directory_readwrite" {
#   principal_object_id = azuread_service_principal.hybrid_identity.object_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Directory.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_app_graph_domain_readwrite" {
#   principal_object_id = azuread_service_principal.hybrid_identity.object_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Domain.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_app_graph_onprem_sync_readwrite" {
#   principal_object_id = azuread_service_principal.hybrid_identity.object_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["OnPremDirectorySynchronization.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_app_graph_organization_readwrite" {
#   principal_object_id = azuread_service_principal.hybrid_identity.object_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Organization.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# # Create a client secret for the app registration
# resource "azuread_application_password" "hybrid_identity" {
#   application_id = azuread_application.hybrid_identity.id
#   display_name   = "hybrid-identity-client-secret"
#   end_date       = timeadd(timestamp(), "8760h") # 1 year from now
# }

# output "mummy" {
#     sensitive = true
#     value = azuread_application_password.hybrid_identity.value
# }

# resource "azuread_app_role_assignment" "hybrid_identity_graph_application_readwrite" {
#   principal_object_id = azurerm_user_assigned_identity.hybrid_identity.principal_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Application.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_graph_directory_read" {
#   principal_object_id = azurerm_user_assigned_identity.hybrid_identity.principal_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Directory.Read.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_graph_directory_readwrite" {
#   principal_object_id = azurerm_user_assigned_identity.hybrid_identity.principal_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Directory.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_graph_domain_readwrite" {
#   principal_object_id = azurerm_user_assigned_identity.hybrid_identity.principal_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Domain.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_graph_onprem_sync_readwrite" {
#   principal_object_id = azurerm_user_assigned_identity.hybrid_identity.principal_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["OnPremDirectorySynchronization.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# resource "azuread_app_role_assignment" "hybrid_identity_graph_organization_readwrite" {
#   principal_object_id = azurerm_user_assigned_identity.hybrid_identity.principal_id
#   app_role_id         = data.azuread_service_principal.microsoft_graph.app_role_ids["Organization.ReadWrite.All"]
#   resource_object_id  = data.azuread_service_principal.microsoft_graph.object_id
# }

# # Note: 'openid', 'email', and 'profile' are delegated permissions, not app roles, and cannot be assigned to managed identities or service principals as application permissions.

# data "azuread_service_principal" "microsoft_graph" {
#   display_name = "Microsoft Graph"
# }
