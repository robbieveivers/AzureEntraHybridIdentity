locals {
  ad_domain = "identity.robertveivers.com"
}

resource "msgraph_update_resource" "enable_sync_on_tenant" {
  url = "organization/{921f7e73-79df-49b6-ac72-da016fcbe938}"
  body = {
    onPremisesSyncEnabled = true
  }
}

resource "azuread_application_from_template" "aad2entra" {
  display_name = "Entra-Cloud-Sync-${local.ad_domain}"
  template_id  = "1a4721b3-e57f-4451-ae87-ef078703ec94" #Idk it didnt find the template from the data block using a display name
  depends_on = [ terraform_data.ansible_provision ]
}

resource "msgraph_resource_action" "entra_cloud_sync_secrets" {
  resource_url   = "servicePrincipals/${azuread_application_from_template.aad2entra.service_principal_object_id}/synchronization/secrets"
  method =  "PUT"
  body = {
    value = [
      {
        key   = "AppKey"
        value = "{\"appKeyScenario\":\"AD2AADPasswordHash\"}"
      },
      {
        key   = "Domain"
        value = "{\"domain\":\"${local.ad_domain}\"}"
      }
    ]
  }
}

#This doesnt seem to have the same issue with multiple jobs being created :)
# Sub resource of the Service Principal that gets created
# Create the synchronization job for Entra Cloud Sync
resource "msgraph_resource" "entra_cloud_sync_job" {
  url = "servicePrincipals/${azuread_application_from_template.aad2entra.service_principal_object_id}/synchronization/jobs"
  body = {
    templateId = "AD2AADProvisioning"
  }
  response_export_values = {
    job_id = "id"
    status = "synchronization.status"
    all    = "@"
  }
}

# Sub resource of the Service Pricipal that gets created
# Create the synchronization job for Entra Cloud Sync
resource "msgraph_resource" "entra_cloud_sync_job_password_hash" {
  url = "servicePrincipals/${azuread_application_from_template.aad2entra.service_principal_object_id}/synchronization/jobs"
  body = {
    templateId = "AD2AADPasswordHash"
  }
  response_export_values = {
    job_id = "id"
    status = "synchronization.status"
    all    = "@"
  }
}

#Okay we need to manage the schema for the Adtoaad job now
# we get a defualt schema but we are required to extend based on a couple things. PHS maybe Customise the target vars in Entra
#or you have directory Extension vars
#https://learn.microsoft.com/en-us/graph/synchronization-configure-with-custom-target-attributes?tabs=http
#https://learn.microsoft.com/en-us/graph/synchronization-configure-with-directory-extension-attributes?tabs=http
# Deleting the Schema Sets it back to defualt
#https://learn.microsoft.com/en-us/graph/api/synchronization-synchronizationschema-delete?view=graph-rest-1.0
#Iv created a job schema json tftpl that contains the base/defualt schema.
# I can now inject any customizations with vars hopefully. Lets just test the basics which no modifcaiton just reupload?

locals {
  # Render the schema content from template plus modifications. (large JSON string)
  schema_content = templatefile("${path.module}/jobschemas/jobschema.json.tftpl", {
    service_principal_object_id = azuread_application_from_template.aad2entra.service_principal_object_id
    synchronization_job_id      = msgraph_resource.entra_cloud_sync_job.output.job_id
  })
}
resource "msgraph_resource_action" "put_schema" {
  resource_url = "servicePrincipals/${azuread_application_from_template.aad2entra.service_principal_object_id}/synchronization/jobs/${msgraph_resource.entra_cloud_sync_job.output.job_id}/schema"
  method       = "PUT"
  body = jsondecode(local.schema_content)
  
}

resource "msgraph_resource_action" "start_job" {
  resource_url = "servicePrincipals/${azuread_application_from_template.aad2entra.service_principal_object_id}/synchronization/jobs/${msgraph_resource.entra_cloud_sync_job.output.job_id}"
  method       = "POST"
  action = "start"
}
