
# data "msgraph_resource" "organization" {
#   url = "organization"
#   response_export_values = {
#     id = "value[0].id"
#   }
# }

locals {
  ad_domain = "identity.robertveivers.com"
}

import {
  to = msgraph_resource.enable_sync
  id = "/organization/{921f7e73-79df-49b6-ac72-da016fcbe938}"
}
## WARNING, NEED TO TEST. Will this destory the org on delete?
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

# Use a null_resource with local-exec to POST to the applicationTemplates instantiate endpoint
resource "terraform_data" "instantiate_cloud_sync_app" {
  provisioner "local-exec" {
    command = <<EOT
        az rest \
        --method post \
        --url "https://graph.microsoft.com/beta/applicationTemplates/1a4721b3-e57f-4451-ae87-ef078703ec94/instantiate" \
        --headers "Content-Type=application/json" \
        --body "{\"displayName\": \"Entra-Cloud-Sync-${local.ad_domain}\"}"
    EOT
    interpreter = ["/bin/bash", "-c"]
  }
}




# POST https://graph.microsoft.com/beta/applicationTemplates/1a4721b3-e57f-4451-ae87-ef078703ec94/instantiate
# Content-type: application/json
# {
#     displayName: [your app name here]
# }


# PATCH https://graph.microsoft.com/v1.0/organization/{organizationId}
# Content-type: application/json
# Content-length: 102

# PATCH https://graph.microsoft.com/v1.0/organization/{organizationId}
# Content-type: application/json
# Content-length: 102

# {
#   "@odata.type": "#microsoft.graph.organization",
#   "mobileDeviceManagementAuthority": "intune"
# }