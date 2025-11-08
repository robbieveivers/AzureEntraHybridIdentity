# Troubleshooting Guide

This guide helps resolve common issues you might encounter when deploying and using this project.

## Table of Contents

- [Authentication Issues](#authentication-issues)
- [Terraform Errors](#terraform-errors)
- [Ansible Connection Problems](#ansible-connection-problems)
- [Cloud Sync Agent Issues](#cloud-sync-agent-issues)
- [Network Connectivity](#network-connectivity)
- [Active Directory Problems](#active-directory-problems)

## Authentication Issues

### Azure CLI Not Authenticated

**Symptoms:**
```
Error: getting authenticated object ID: obtaining authentication token: executing Azure CLI: Error retrieving token from Azure CLI
```

**Solution:**
```bash
# Login to Azure
az login

# Verify you're logged in
az account show

# If you have multiple subscriptions, set the correct one
az account set --subscription "Your-Subscription-Name"
```

### Token Acquisition Failed

**Symptoms:**
- `get-token.sh` fails with error messages
- "Not logged in to Azure CLI" error

**Solution:**
1. Ensure Azure CLI is installed: `az --version`
2. Login with correct permissions: `az login`
3. Verify you have Hybrid Identity Administrator role in Entra ID
4. Check token script permissions: `chmod +x get-token.sh`

## Terraform Errors

### Variable Validation Failed

**Symptoms:**
```
Error: Invalid value for variable
```

**Solution:**
1. Check `terraform.tfvars` format:
   - `subscription_id` must be a valid UUID
   - `ad_password` must be at least 12 characters
   - `location` must be a valid Azure region

2. Example valid configuration:
   ```hcl
   subscription_id = "12345678-1234-1234-1234-123456789012"
   ad_password = "MyStr0ngP@ssw0rd123!"
   location = "eastus"
   ```

### Resource Already Exists

**Symptoms:**
```
Error: A resource with the ID "..." already exists
```

**Solution:**
```bash
# Option 1: Import existing resource
terraform import azurerm_resource_group.rg /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP_NAME

# Option 2: Destroy and recreate
terraform destroy
terraform apply

# Option 3: Change resource names in terraform.tfvars or main.tf
```

### Backend Initialization Failed

**Symptoms:**
```
Error: Failed to get existing workspaces
```

**Solution:**
```bash
# Remove Terraform state and reinitialize
rm -rf .terraform
rm -rf .terraform.lock.hcl
terraform init
```

## Ansible Connection Problems

### WinRM Connection Timeout

**Symptoms:**
```
UNREACHABLE! => {"changed": false, "msg": "connection timeout"}
```

**Solutions:**

1. **Verify VM is running:**
   ```bash
   az vm show -g win2025-rg -n domain-win25 --query "powerState" -o tsv
   ```

2. **Check NSG rules allow your IP:**
   ```bash
   # Get your current IP
   curl https://api.ipify.org/
   
   # Verify it matches the NSG rule
   az network nsg rule show -g win2025-rg --nsg-name win2025-nsg -n Allow-Winrm-Http
   ```

3. **Wait longer - VM might still be booting:**
   - Windows Server needs 5-10 minutes after creation
   - Check boot diagnostics in Azure Portal

4. **Test connectivity manually:**
   ```bash
   # Test if port 5985 is open
   nc -zv <VM_PUBLIC_IP> 5985
   ```

### Authentication Failed

**Symptoms:**
```
fatal: [IP]: FAILED! => {"msg": "winrm send_input failed"}
```

**Solution:**
1. Verify credentials in `terraform.tfvars`
2. Check password meets complexity requirements
3. Ensure WinRM is enabled on the VM

## Cloud Sync Agent Issues

### Agent Installation Failed

**Symptoms:**
- Ansible task "Install Entra Cloud Sync Provisioning Agent" fails
- Installation hangs indefinitely

**Solutions:**

1. **Check download URL is accessible:**
   - Verify subscription_id is correct
   - Ensure VM has internet connectivity

2. **Manual installation verification:**
   - RDP to the VM
   - Check Event Viewer → Applications and Services Logs → Microsoft → AzureAD → ConnectProvisioningAgent

3. **Retry installation:**
   ```bash
   # Destroy and recreate
   terraform destroy -target=azurerm_windows_virtual_machine.vm
   terraform apply
   ```

### Agent Registration Failed

**Symptoms:**
```
Connect-AADCloudSyncAzureAD : Unable to authenticate
```

**Solutions:**

1. **Verify token is valid:**
   ```bash
   # Get a fresh token
   ./get-token.sh
   ```

2. **Check account permissions:**
   - Must have Hybrid Identity Administrator role
   - Must be in the correct tenant

3. **Verify internet connectivity from VM:**
   - Check firewall rules
   - Ensure outbound HTTPS (443) is allowed
   - Test connectivity to `*.msappproxy.net`

### gMSA Creation Failed

**Symptoms:**
```
Add-AADCloudSyncGMSA : The operation failed
```

**Solutions:**

1. **Verify domain is ready:**
   - Allow more time after domain creation (10-15 minutes)
   - Check domain services are running

2. **Check KDS Root Key:**
   RDP to VM and run:
   ```powershell
   Get-KdsRootKey
   # Should show at least one key
   ```

3. **Verify domain admin credentials:**
   - Ensure password is correct
   - Check account has Domain Admin privileges

## Network Connectivity

### Cannot Access VM

**Symptoms:**
- Cannot connect via RDP
- Azure Bastion shows connection error

**Solutions:**

1. **Verify NSG rules:**
   ```bash
   az network nsg rule list -g win2025-rg --nsg-name win2025-nsg -o table
   ```

2. **Check your current IP:**
   ```bash
   curl https://api.ipify.org/
   ```

3. **Update NSG if IP changed:**
   ```bash
   # Destroy and recreate (will update with current IP)
   terraform destroy -target=azurerm_network_security_group.nsg
   terraform apply
   ```

4. **Use Azure Bastion instead of direct RDP:**
   - More secure
   - Doesn't require public IP access
   - Wait for Bastion deployment to complete

### DNS Resolution Issues

**Symptoms:**
- Cannot resolve domain names
- Cloud Sync cannot connect to Azure

**Solution:**
1. Check VM DNS settings
2. Verify Azure-provided DNS is configured
3. Test with `nslookup` from VM

## Active Directory Problems

### Domain Promotion Failed

**Symptoms:**
```
microsoft.ad.domain : Failed to promote server to domain controller
```

**Solutions:**

1. **Check disk space:**
   ```powershell
   Get-PSDrive C | Select-Object Used, Free
   ```

2. **Verify NetBIOS name is valid:**
   - Must be 15 characters or less
   - No special characters
   - All uppercase

3. **Check domain name DNS format:**
   - Must be valid DNS name
   - Example: `contoso.local`, `corp.example.com`

4. **Review Windows Event Logs:**
   - RDP to VM
   - Event Viewer → Windows Logs → System
   - Look for Directory Services errors

### Cannot Join Domain

**Symptoms:**
- Other machines cannot join the deployed domain
- DNS lookups fail

**Solutions:**

1. **Verify DNS configuration:**
   - Point client machines to DC IP address for DNS
   - Test: `nslookup domain.name DC_IP`

2. **Check firewall rules:**
   - AD requires multiple ports
   - Ensure NSG allows necessary traffic

3. **Verify domain functional level:**
   ```powershell
   Get-ADDomain | Select-Object DomainMode
   ```

## Getting Help

If you're still experiencing issues:

1. **Check Azure Portal:**
   - Resource health status
   - Activity log for errors
   - Boot diagnostics

2. **Review logs:**
   - Terraform logs: `TF_LOG=DEBUG terraform apply`
   - Ansible verbose output: Use `-vvv` flag
   - Azure VM logs via Serial Console

3. **Community support:**
   - Open an issue on GitHub
   - Include error messages
   - Provide environment details
   - Redact sensitive information

4. **Azure Support:**
   - For Azure infrastructure issues
   - Entra ID configuration problems
   - Billing or subscription issues

## Prevention Tips

1. **Always use latest version:**
   ```bash
   git pull origin main
   ```

2. **Keep tools updated:**
   ```bash
   terraform version
   ansible --version
   az version
   ```

3. **Test in dev environment first:**
   - Use separate subscription for testing
   - Don't test in production

4. **Regular backups:**
   - Export Terraform state
   - Backup VM snapshots
   - Document custom configurations

5. **Monitor deployments:**
   - Watch Terraform output carefully
   - Review Ansible task results
   - Check Azure Portal after deployment
