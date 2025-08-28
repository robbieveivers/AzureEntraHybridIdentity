
# data "msgraph_resource" "organization" {
#   url = "organization"
#   response_export_values = {
#     id = "value[0].id"
#   }
# }

locals {
  ad_domain = "identity.robertveivers.com"
}

variable "entra_cloud_sync_sp_id" {
  description = "Optional: Pre-provided service principal ID for the Entra Cloud Sync Enterprise App. If set, avoids reading from local file."
  type        = string
  default     = null
}

import {
  to = msgraph_resource.enable_sync
  id = "/organization/{921f7e73-79df-49b6-ac72-da016fcbe938}"
}
## WARNING, NEED TO TEST. Will this destory the org on delete?
#Pretty sure if your a paying entra p1 above you might be able to create the entra via
resource "msgraph_resource" "enable_sync" {
  url = "organization"
  body = {
    technicalNotificationMails = ["robbieveivers@outlook.com"]
    onPremisesSyncEnabled      = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

## WARNING, NEED TO TEST. im sure we likly will need to take control of the app once its created?
# resource "msgraph_resource" "enable_sync_service_principal" {
#   url = "applicationTemplates/1a4721b3-e57f-4451-ae87-ef078703ec94/instantiate"
#   body = {
#     displayName = "Entra-Cloud-Sync-${local.ad_domain}"
#   }
#   #microsoft.graph.instantiate is the post call tho..
#   lifecycle {
#     prevent_destroy = true
#     ignore_changes = all
#   }

# }
############### Commenting out it i want to document why i couldnt do it. Could the provider handle these in future.
# Will likly have a resource_action for graph api at some point to replace this terraform_data similar to azapi
#https://registry.terraform.io/providers/Azure/azapi/latest/docs/resources/resource_action
# Use the built-in external data source to call Microsoft Graph and return a small JSON
# This runs `az rest` and pipes the response to `jq` inline (no temp files).
# data "external" "instantiate_cloud_sync_app" {
#   program = [
#     "bash",
#     "-c",
#     "az rest --method post --url 'https://graph.microsoft.com/beta/applicationTemplates/1a4721b3-e57f-4451-ae87-ef078703ec94/instantiate' --headers 'Content-Type=application/json' --body '{\"displayName\": \"Entra-Cloud-Sync-${local.ad_domain}\"}' | jq -c '{service_principal_object_id: .servicePrincipal.objectId, app_object_id: .application.objectId, app_id: .application.appId, tenant_id: .servicePrincipal.appOwnerTenantId}'"
#   ]
# }

# Entra Cloud Sync Application Template Instantiation
# Using terraform_data for action-based API call that should only run once
resource "terraform_data" "entra_cloud_sync_app" {
  provisioner "local-exec" {
  command = "SP_ID=$(az rest --method post --url \"https://graph.microsoft.com/v1.0/applicationTemplates/1a4721b3-e57f-4451-ae87-ef078703ec94/instantiate\" --headers \"Content-Type=application/json\" --body '{\"displayName\": \"Entra-Cloud-Sync-${local.ad_domain}\"}' --query 'servicePrincipal.id' --output tsv); printf '%s' \"$SP_ID\" > ${path.module}/.entra_cloud_sync_sp_id"
    interpreter = ["/bin/bash", "-c"]
  }

  # Clean up the temp file on destroy
  provisioner "local-exec" {
    when    = destroy
    command = "rm -f ${path.module}/.entra_cloud_sync_sp_id"
    interpreter = ["/bin/bash", "-c"]
  }
}

# Read the service principal ID from the file
data "local_file" "entra_cloud_sync_sp_id" {
  filename   = "${path.module}/.entra_cloud_sync_sp_id"
  depends_on = [terraform_data.entra_cloud_sync_app]
}

# Output the service principal ID for use in other resources  
output "entra_cloud_sync_service_principal_id" {
  value = trimspace(data.local_file.entra_cloud_sync_sp_id.content)
  description = "The service principal ID of the Entra Cloud Sync application Object. We need this for the next step."
}

#There really needs to be some kind to wait between these two resources. Becasue the SP isnt fulled created so the sync job i thik fails. 

# Create the synchronization job for Entra Cloud Sync
resource "msgraph_resource" "entra_cloud_sync_job" {
  api_version = "beta"
  url         = "servicePrincipals/${trimspace(coalesce(var.entra_cloud_sync_sp_id, data.local_file.entra_cloud_sync_sp_id.content))}/synchronization/jobs"
  
  body = {
    templateId = "AD2AADProvisioning"
  }
  
  response_export_values = {
    job_id = "id"
    status = "synchronization.status"
    all    = "@"
  }
  
  depends_on = [terraform_data.entra_cloud_sync_app]
}

# Create the synchronization job for Entra Cloud Sync
resource "msgraph_resource" "entra_cloud_sync_job_password_hash" {
  api_version = "beta"
  url         = "servicePrincipals/${trimspace(coalesce(var.entra_cloud_sync_sp_id, data.local_file.entra_cloud_sync_sp_id.content))}/synchronization/jobs"
  
  body = {
    templateId = "AD2AADPasswordHash"
  }
  
  response_export_values = {
    job_id = "id"
    status = "synchronization.status"
    all    = "@"
  }
  
  depends_on = [terraform_data.entra_cloud_sync_app]
}

# # Output the sync job ID for future reference
# output "entra_cloud_sync_job_id" {
#   value       = msgraph_resource.entra_cloud_sync_job.output.job_id
#   description = "The synchronization job ID for the Entra Cloud Sync application"
# }
