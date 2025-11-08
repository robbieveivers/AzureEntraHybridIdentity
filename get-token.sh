#!/usr/bin/env bash
set -euo pipefail

# Script to retrieve Azure AD access token for Cloud Sync agent registration
# Requires: Azure CLI (az) to be installed and authenticated

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo '{"error": "Azure CLI (az) is not installed or not in PATH"}' >&2
    exit 1
fi

# Check if user is logged in to Azure CLI
if ! az account show &> /dev/null; then
    echo '{"error": "Not logged in to Azure CLI. Please run: az login"}' >&2
    exit 1
fi

# Get the access token
token=$(az account get-access-token \
    --resource-type 'aad-graph' \
    --scope 'https://proxy.cloudwebappproxy.net/registerapp/user_impersonation' \
    --query accessToken -o tsv 2>&1)

# Check if token retrieval was successful
if [ $? -ne 0 ] || [ -z "$token" ]; then
    echo '{"error": "Failed to retrieve access token"}' >&2
    exit 1
fi

# Output the token in JSON format
echo '{"access_token": "'$token'"}'