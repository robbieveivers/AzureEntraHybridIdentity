#!/usr/bin/env bash

token=$(az account get-access-token --resource-type 'aad-graph' --scope 'https://proxy.cloudwebappproxy.net/registerapp/user_impersonation' --query accessToken -o tsv)
echo '{"access_token": "'$token'"}'