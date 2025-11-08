#!/usr/bin/env bash
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Print banner
echo "=================================================="
echo "  Azure Entra Hybrid Identity Deployment Script  "
echo "=================================================="
echo ""

# Check prerequisites
print_info "Checking prerequisites..."

if ! command_exists terraform; then
    print_error "Terraform is not installed. Please install it first."
    exit 1
fi
print_success "Terraform is installed"

if ! command_exists ansible; then
    print_error "Ansible is not installed. Please install it first."
    exit 1
fi
print_success "Ansible is installed"

if ! command_exists az; then
    print_error "Azure CLI is not installed. Please install it first."
    exit 1
fi
print_success "Azure CLI is installed"

# Check Azure authentication
print_info "Checking Azure authentication..."
if ! az account show &>/dev/null; then
    print_error "Not logged in to Azure CLI. Please run: az login"
    exit 1
fi

ACCOUNT_NAME=$(az account show --query "user.name" -o tsv)
SUBSCRIPTION_NAME=$(az account show --query "name" -o tsv)
print_success "Authenticated as: $ACCOUNT_NAME"
print_info "Using subscription: $SUBSCRIPTION_NAME"

# Check if terraform.tfvars exists
if [ ! -f "terraform.tfvars" ]; then
    print_warning "terraform.tfvars not found"
    
    if [ -f "terraform.tfvars.example" ]; then
        print_info "Creating terraform.tfvars from example..."
        cp terraform.tfvars.example terraform.tfvars
        print_warning "Please edit terraform.tfvars with your values before continuing!"
        print_info "Required fields:"
        echo "  - ad_password (minimum 12 characters)"
        echo "  - subscription_id"
        echo ""
        read -p "Press Enter after you've updated terraform.tfvars, or Ctrl+C to exit..."
    else
        print_error "terraform.tfvars.example not found. Cannot create terraform.tfvars"
        exit 1
    fi
fi

# Validate terraform.tfvars has required values
print_info "Validating terraform.tfvars..."

if grep -q 'subscription_id = ""' terraform.tfvars; then
    print_error "subscription_id is empty in terraform.tfvars"
    exit 1
fi

if grep -q 'ad_password = ""' terraform.tfvars; then
    print_error "ad_password is empty in terraform.tfvars"
    exit 1
fi

print_success "Configuration looks good"

# Initialize Terraform
print_info "Initializing Terraform..."
if terraform init; then
    print_success "Terraform initialized"
else
    print_error "Terraform initialization failed"
    exit 1
fi

# Validate Terraform configuration
print_info "Validating Terraform configuration..."
if terraform validate; then
    print_success "Configuration is valid"
else
    print_error "Terraform validation failed"
    exit 1
fi

# Run Terraform plan
print_info "Running Terraform plan..."
if terraform plan -out=tfplan; then
    print_success "Plan created successfully"
else
    print_error "Terraform plan failed"
    exit 1
fi

# Ask for confirmation
echo ""
print_warning "Review the plan above carefully!"
echo ""
read -p "Do you want to apply this plan? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    print_info "Deployment cancelled"
    rm -f tfplan
    exit 0
fi

# Apply Terraform configuration
print_info "Applying Terraform configuration..."
print_warning "This will take 20-30 minutes. Do not interrupt!"
echo ""

if terraform apply tfplan; then
    print_success "Deployment completed successfully!"
    echo ""
    print_info "Deployment details:"
    terraform output
    echo ""
    print_success "You can now connect to your VM using Azure Bastion"
    print_info "Check the Azure Portal or use the connection instructions above"
else
    print_error "Terraform apply failed"
    rm -f tfplan
    exit 1
fi

# Cleanup
rm -f tfplan

print_success "All done! 🎉"
