# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive README with improved documentation
- LICENSE file (MIT License)
- CONTRIBUTING.md with contribution guidelines
- SECURITY.md with security best practices and reporting guidelines
- ARCHITECTURE.md with detailed system architecture documentation
- CHANGELOG.md for tracking changes
- outputs.tf for exposing deployment information
- Input validation for Terraform variables (location, password, subscription_id)
- Tags variable for resource organization
- Resource tags applied to all Azure resources
- GitHub Actions workflow for Terraform validation
- Markdown linting configuration
- Ansible linting in CI/CD pipeline
- .editorconfig for consistent coding style
- Improved terraform.tfvars.example with comments

### Changed
- Enhanced README with better structure, emojis, and clearer instructions
- Improved .gitignore to exclude IDE files, logs, and environment files
- Enhanced get-token.sh with error handling and validation
- Better error messages in shell scripts

### Fixed
- Typos in README ("involes" → "involves", "dangours" → "dangerous")
- Grammar and clarity improvements throughout documentation

## [1.0.0] - Initial Release

### Added
- Initial Terraform configuration for Azure infrastructure
- Ansible playbook for AD DS and Cloud Sync agent deployment
- Dev container configuration for development environment
- Basic documentation
