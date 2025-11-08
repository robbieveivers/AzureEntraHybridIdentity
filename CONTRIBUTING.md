# Contributing to Azure Entra Hybrid Identity

Thank you for your interest in contributing to this project! We welcome contributions from the community.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improvement:

1. Check if the issue already exists in the [Issues](../../issues) section
2. If not, create a new issue with:
   - A clear, descriptive title
   - Detailed description of the problem or suggestion
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Your environment details (OS, Terraform version, etc.)

### Submitting Changes

1. **Fork the repository**
   ```bash
   git clone https://github.com/robbieveivers/AzureEntraHybridIdentity.git
   cd AzureEntraHybridIdentity
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Update documentation if needed
   - Test your changes thoroughly

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Brief description of changes"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Explain the motivation behind the changes

## Development Guidelines

### Terraform Best Practices

- Use meaningful resource names
- Add descriptions to all variables
- Use variables instead of hard-coded values
- Add appropriate tags to resources
- Validate your configuration: `terraform validate`
- Format your code: `terraform fmt`

### Ansible Best Practices

- Use descriptive task names
- Handle errors appropriately
- Make playbooks idempotent
- Use variables for configuration
- Document any non-obvious steps

### Security

- Never commit sensitive data (passwords, tokens, keys)
- Use `.tfvars` files for sensitive configuration
- Follow the principle of least privilege
- Review security implications of changes

### Testing

Before submitting:

1. Run `terraform fmt` to format code
2. Run `terraform validate` to check syntax
3. Test deployment in a safe environment
4. Document any new configuration options

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the technical merits of contributions
- Help create a welcoming environment for all

## Questions?

Feel free to open an issue for questions or discussion!

Thank you for contributing! 🎉
