# AzureEntraHybridIdentity
Repo for Standing up Infra for Entra Hybrid Identity Testing

## Create Vnet

## Create KeyVault

## Create Linux Ansible Controller

## Create Bastion for remoting into Ansible Controller and or Windows VMs


# Required VS code modules for connectin via bastion

Name: Remote - SSH
Id: ms-vscode-remote.remote-ssh
Description: Open any folder on a remote machine using SSH and take advantage of VS Code's full feature set.
Version: 0.112.0
Publisher: Microsoft
VS Marketplace Link: https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh

### Adding the SSH Ansible host
Add new SSH Host
- ansibleadmin@<BastionHostPublicIP>
Specify ssh custom ssh config


az keyvault secret show --name "ansiblecontroller-private-key" --vault-name "kv-robbiecorp" --query value -o tsv > ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa


Host bastion
  HostName <BastionHostPublicIP>
  User ansibleadmin
  IdentityFile ~/.ssh/id_rsa

Host target-vm
  HostName <TargetVMPrivateIP>
  User ansibleadmin
  IdentityFile ~/.ssh/id_rsa
  ProxyCommand ssh -W %h:%p ansibleadmin@<BastionHostPublicIP>