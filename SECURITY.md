# Security Policy

## Supported Versions

This project is actively maintained. Please use the latest version from the main branch.

## Reporting a Vulnerability

If you discover a security vulnerability, please do NOT open a public issue. Instead:

1. Email the repository owner directly through GitHub
2. Provide a detailed description of the vulnerability
3. Include steps to reproduce if possible
4. Allow reasonable time for the issue to be addressed before public disclosure

## Security Best Practices

### Authentication & Authorization

- **Never use Global Admin accounts** for deployment
- Use dedicated accounts with minimal required permissions:
  - Hybrid Identity Administrator role for Entra ID
  - Contributor role (or more restrictive) for Azure subscription
- Regularly rotate credentials and tokens
- Enable MFA on all administrative accounts

### Credential Management

- **Never commit sensitive data** to version control:
  - Passwords
  - Access tokens
  - API keys
  - Subscription IDs
  - Tenant IDs
- Use `terraform.tfvars` (gitignored) for sensitive configuration
- Consider using Azure Key Vault for production deployments
- Use strong passwords (minimum 12 characters, mix of upper/lower/numbers/symbols)

### Network Security

- The deployment restricts access to your current IP address only
- Review and adjust NSG rules based on your security requirements
- Consider using Azure Bastion exclusively (disable RDP public access)
- Use HTTPS for WinRM in production (this project uses HTTP for testing)
- Regularly review and audit network access logs

### Infrastructure Security

- Review all Terraform changes before applying
- Use `terraform plan` to preview changes
- Implement Azure Policy for compliance requirements
- Enable Azure Security Center recommendations
- Regularly update and patch deployed resources

### Token Handling

- Tokens obtained via `get-token.sh` are short-lived
- Never log or display tokens in plain text
- Tokens are marked as sensitive in Terraform
- Rotate credentials if token exposure is suspected

### Development Environment

- Use dev containers or isolated environments
- Don't run Terraform from production credential contexts
- Separate testing and production environments
- Use different subscriptions for dev/test/prod

## Known Security Considerations

1. **HTTP WinRM**: The deployment uses HTTP for WinRM during provisioning. This is acceptable for testing environments but should be HTTPS in production.

2. **Public IP**: The VM is assigned a public IP for initial setup. Consider removing this after configuration or using only Azure Bastion.

3. **Token Scope**: The deployment requires broad AAD Graph permissions. This is inherent to the Cloud Sync agent registration process.

4. **Password Storage**: Terraform state files contain sensitive data. Secure your state files appropriately (use remote state with encryption).

## Security Updates

Check for updates regularly:
- Terraform provider versions
- Ansible collection versions
- Base VM images
- Dependencies in dev containers

## Compliance

This project creates resources that may need to comply with:
- Your organization's security policies
- Industry regulations (GDPR, HIPAA, etc.)
- Azure security baselines

Review all configurations against your compliance requirements before deployment.

## Questions?

For security-related questions that are not vulnerabilities, please open a GitHub issue or discussion.
