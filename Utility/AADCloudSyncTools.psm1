<#
Disclaimer: The scripts are not supported under any Microsoft standard support program or service. 
The scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all implied 
warranties including, without limitation, any implied warranties of merchantability or of fitness for a 
particular purpose. The entire risk arising out of the use or performance of the scripts and 
documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the 
creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without 
limitation, damages for loss of business profits, business interruption, loss of business information, or 
other pecuniary loss) arising out of the use of or inability to use the scripts or documentation, 
even if Microsoft has been advised of the possibility of such damages. 
#>

#=======================================================================================
#region Internal Functions
#=======================================================================================

Function IsPowerShellModulePresent
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true)] 
        $ModuleName
    )

    Write-Verbose "Checking $ModuleName module..."
    $poshModule = Get-Module -Name $ModuleName -ListAvailable

    if ($poshModule -eq $null) 
    {
        Throw "$ModuleName Powershell module is not installed. Please try 'Install-AADCloudSyncToolsPrerequisites' from an elevated PowerShell session."
    }
}

Function IsAgentPresent
{
    If ($script:AADCloudSyncTools.AgentPresent -eq $false)
    {
        Throw "To use this function you need to have Microsoft Azure AD Cloud Sync Agent installed and configured."
    }
}

Function IsTenantIdPresent
{
    Return ($script:AADCloudSyncTools.TenantId -notlike "")
}

Function IsAADCloudSyncToolsConnected
{
    Param
    (
        [parameter(Mandatory = $false)] 
        [switch]
        $DontThrowError
    )

    If (-not ($script:AADCloudSyncTools.Connected))
    {
        [string] $message = "`nPlease start with 'Connect-AADCloudSyncTools [-LoginHint <UserPrincipalName>]' before calling any other cmdlets.`n"        
        if ($DontThrowError)
        {
            Write-Host $message -ForegroundColor Cyan
        }
        Else
        {
            Throw $message
        }
    }

}

Function IsPowerShellSessionElevated
{
    If (([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
    {
        Throw "To use this function you need Administrator privileges. Please start PowerShell with 'Run As Administrator'."
    }
}

Function InitInternalModuleVariables
{
    [CmdletBinding()]
    Param()

    $warningMsg = "Microsoft Azure AD Cloud Sync Agent [msgPlaceholder] not present or cannot be found. Some functionally may not be available."
    $script:AADCloudSyncTools = "" | 
        Select TenantId, ClientId, Username, Connected, Header, AwsToken, AccessToken, AgentServiceName, `
            ConfigDirSource, ConfigFileSource, ConfigPathTarget, LogDirTarget, LogFileTarget, `
            ReplicationDelay, MaxRetries, AgentPresent, Scopes, PAClientId
    
    Try
    {
        [string] $script:AADCloudSyncTools.PAClientId = 'cb1056e2-e479-49de-ae31-7812af012ed8'
        [string[]] $script:AADCloudSyncTools.Scopes = @('https://graph.windows.net/user_impersonation')
        Write-verbose "Reading Cloud Sync Agent config from registry..."
        $aadCloudSyncAgentReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Provisioning Agent" -ErrorAction Stop
        $script:AADCloudSyncTools.AgentPresent = $true
    }
    Catch
    {
        Write-Warning "$($warningMsg.Replace("[msgPlaceholder]", "registry key is")) Error Details: $($_.Exception.Message)"
        $script:AADCloudSyncTools.AgentPresent = $false
    }


    If ($AADCloudSyncTools.AgentPresent -eq $true)
    {
        # Read Cloud Sync Agent config settings
        Write-verbose "Reading Cloud Sync Agent settings..."
        [string] $script:AADCloudSyncTools.AgentServiceName = $aadCloudSyncAgentReg.ServiceName
        [string] $script:AADCloudSyncTools.ConfigDirSource = $aadCloudSyncAgentReg.InstallDir
        [string] $script:AADCloudSyncTools.ConfigFileSource = $aadCloudSyncAgentReg.ServiceProcessName + ".config"

        # Set target path for config file and trace logs
        [string] $script:AADCloudSyncTools.LogFileTarget    = 'trace-agent-verbose'
        Try
        {
            Write-verbose "Reading Cloud Sync Agent file and log path..."
            [string] $script:AADCloudSyncTools.ConfigPathTarget = Join-Path -Path $script:AADCloudSyncTools.ConfigDirSource -ChildPath $script:AADCloudSyncTools.ConfigFileSource -ErrorAction Stop
        }
        Catch
        {
            Write-Warning "$($warningMsg.Replace("[msgPlaceholder]", "path is")) Error Details: $($_.Exception.Message)"
            $AADCloudSyncTools.AgentPresent = $false
        }

        # Check if ProgramData path exists
        Write-verbose "Checking ProgramData path..."
        If ($aadCloudSyncAgentReg.ProgramDataFolderName -ne $null)
        {
            [string] $script:AADCloudSyncTools.LogDirTarget  = Join-Path -Path 'C:\ProgramData\Microsoft\' -ChildPath "$($aadCloudSyncAgentReg.ProgramDataFolderName)\Trace" -ErrorAction Stop            
        }
        Else
        {
            Write-Warning "$($warningMsg.Replace("[msgPlaceholder]", "ProgramData path is"))"
            $AADCloudSyncTools.AgentPresent = $false
        }

        # Check if config file exists
        If (($script:AADCloudSyncTools.ConfigPathTarget -ne $null) -and (-not (Test-Path $script:AADCloudSyncTools.ConfigPathTarget))) 
        {
            Write-verbose "Checking config file path..."
            Write-Warning "$($warningMsg.Replace("[msgPlaceholder]", "config file is"))"
            $AADCloudSyncTools.AgentPresent = $false
        }
    }

    # Check if TenantId is present in Registry and prompt if missing
    [string] $script:AADCloudSyncTools.TenantId = $aadCloudSyncAgentReg.TenantID
    Write-verbose "Checking TenantId..."
    if (-not (IsTenantIdPresent))
    {
        $userTenantId = Read-Host "$($warningMsg.Replace("[msgPlaceholder]", "TenantId")) Please provide a TenantId"
        Try
        {
            $script:AADCloudSyncTools.TenantId = [guid] $userTenantId
        }
        Catch
        {
            Throw "Invalid TenantId. Cannot import Microsoft Azure AD Cloud Sync Tools module."
        }
    }
    Else
    {
        Write-Host "`nAzure AD Cloud Sync Agent configured with TenantId '$($script:AADCloudSyncTools.TenantId)'" -ForegroundColor Cyan
    }

    # Set more internal variables
    [string] $script:AADCloudSyncTools.ClientId = '1950a258-227b-4e31-a9cf-717495945fc2'   # Well-known client ID for Azure AD PowerShell
    [int] $script:AADCloudSyncTools.ReplicationDelay = 5
    [int] $script:AADCloudSyncTools.MaxRetries = 10
    [bool]   $script:AADCloudSyncTools.Connected = $false

    # Write-Verbose internal variables 
    Get-Member -InputObject $script:AADCloudSyncTools -MemberType NoteProperty | %{$prop = $_.Name ; Write-Verbose "$($prop): $($script:AADCloudSyncTools.$prop)" }
}

Function Backup-AADCloudSyncToolsAgentConfigFile
{
    [CmdletBinding()]
    Param()

    [string] $currentDateTimeStr  = Get-AADCloudSyncToolsCurrentDateTimeString

    # Check if backup file exists
    $configBakFileSource = Get-ChildItem -Path $script:AADCloudSyncTools.ConfigDirSource -Filter "$($script:AADCloudSyncTools.ConfigFileSource)*.bak" -File

    If ($configBakFileSource -eq $null)
    {
        # Backup AADConnectProvisioningAgent.exe.config
        [string] $configBakFileSource = $script:AADCloudSyncTools.ConfigFileSource + "-$($currentDateTimeStr).bak"
        [string] $configBakPathTarget = Join-Path -Path $script:AADCloudSyncTools.ConfigDirSource -ChildPath $configBakFileSource
        Write-Verbose "configBakPathTarget: $configBakPathTarget"

        Try
        {
            Write-Verbose "Creating a backup copy of '$($script:AADCloudSyncTools.ConfigFileSource)' to '$configBakPathTarget'"
            Rename-Item -Path $script:AADCloudSyncTools.ConfigPathTarget -NewName $configBakPathTarget
            Copy-Item -Path $configBakPathTarget -Destination $script:AADCloudSyncTools.ConfigPathTarget
        }
        Catch
        {
            Throw "There was a problem creating a backup of the Config file. Error Details: $($_.Exception.Message)"
        }
    }
    Else
    {
        Write-Verbose "Backup copy of '$()' already exists in '$configBakFileSource'"
    }

    # And also return the target verbose log filename based on currentDateTimeStr
    [string] $logPathTarget   = Join-Path -Path $script:AADCloudSyncTools.LogDirTarget  -ChildPath "$($script:AADCloudSyncTools.LogFileTarget)-$currentDateTimeStr.log"
    Return $logPathTarget
}

Function Set-AADCloudSyncToolsAgentConfigFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateSet("Default", "VerboseTracing")]
        [string] 
        $Config = "Default"
    )
    IsPowerShellSessionElevated

    [string] $logPathTarget = Backup-AADCloudSyncToolsAgentConfigFile

    # Read Config file
    Try
    {
        [xml] $configXmlTarget = Get-Content -Path $script:AADCloudSyncTools.ConfigPathTarget -Raw
    }
    Catch
    {
        Throw "There was a problem reading the config file. Error Details: $($_.Exception.Message)"
    }

    # Clean-up system.diagnostics
    if ($configXmlTarget.configuration.'system.diagnostics'.HasChildNodes)
    {
        $childNode = $configXmlTarget.configuration.'system.diagnostics'
        Write-Verbose "Removing Xml node: $($childNode.toString())"
        $configXmlTarget.configuration.RemoveChild($childNode) | Out-Null
    }
    
    # Set 'system.diagnostics' node based on Config parameter
    Switch ($Config)
    {
        'VerboseTracing' 
        {
        $diagnosticsXmlNode = @"
<trace autoflush="true" indentsize="4">
      <listeners>
        <add name="consoleListener" type="System.Diagnostics.ConsoleTraceListener" />
        <remove name="Default" />
      </listeners>
    </trace>
    <sources>
      <source name="AAD Connect Provisioning Agent">
        <listeners>
          <add name="console" />
          <add name="etw" />
        </listeners>
      </source>
    </sources>
    <sharedListeners>
      <add name="console" type="System.Diagnostics.ConsoleTraceListener" initializeData="false" />
      <add name="etw" type="System.Diagnostics.TextWriterTraceListener" initializeData="$logPathTarget" />
    </sharedListeners>
  
"@
        }
        Default 
        {
        $diagnosticsXmlNode = @"
<trace autoflush="true" indentsize="4">
      <listeners>
        <add name="consoleListener" type="System.Diagnostics.ConsoleTraceListener"/>
        <remove name="Default"/>
      </listeners>
    </trace>
  
"@
        }
    }

    # Append 'system.diagnostics' child node
    $diagnosticsChildNode = $configXmlTarget.CreateElement("system.diagnostics")
    $diagnosticsChildNode.InnerXml = $diagnosticsXmlNode
    Write-Verbose "Appending Xml node: $($diagnosticsChildNode.toString())"
    $configXmlTarget.configuration.AppendChild($diagnosticsChildNode) | Out-Null

    # Save Xml Config file
    $configXmlTarget.Save($script:AADCloudSyncTools.ConfigPathTarget)
}

Function Restart-AADCloudSyncToolsAgent
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [bool] $RestartNow
    )

    Write-Verbose "RestartService: $RestartNow"
    If($RestartNow)
    {
        Write-Verbose "'$($script:AADCloudSyncTools.AgentServiceName)' Service will be restarted."
        Restart-Service $script:AADCloudSyncTools.AgentServiceName
    }
    Else
    {
        Write-Warning "Config changes will not take effect until '$($script:AADCloudSyncTools.AgentServiceName)' Service is restarted."
    }
}

Function Request-AADCloudSyncToolsRefreshToken
{
    [cmdletbinding()]
    Param()
    
    IsAADCloudSyncToolsConnected

    # Refresh Access Token
    Write-Verbose "Calling Get-MsalToken: Get-MsalToken -ClientId $($script:AADCloudSyncTools.ClientId) -TenantId $($script:AADCloudSyncTools.TenantId) -Silent -LoginHint $($script:AADCloudSyncTools.Username)"
    $script:AADCloudSyncTools.AccessToken = Get-MsalToken -ClientId $script:AADCloudSyncTools.ClientId -TenantId $script:AADCloudSyncTools.TenantId -Silent -LoginHint $script:AADCloudSyncTools.Username

    # Get Access Token CreateAuthorizationHeader()
    Try
    {
        $script:AADCloudSyncTools.Header = @{
            'Content-Type'  = 'application\json'
            'Authorization' = $script:AADCloudSyncTools.AccessToken.CreateAuthorizationHeader()
        }
    }
    Catch
    {
        Throw "There was a problem creating access token authorization header."
    }

    Write-Verbose "Access Token: $($script:AADCloudSyncTools.AccessToken)"
}

Function Get-AADCloudSyncToolsServicePrincipalFromSyncJob
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $Id
    )

    Write-Verbose "Get Service Principal Id from Sync Job..."    
    $results = @(Get-AADCloudSyncToolsJob -Id $Id -RawData)

    If ($results.Count -gt 0)
    {
	    [string] $servicePrincipalId = $results[0].serviceprincipalId
        Write-Verbose "Returning ServicePrincipalId: $servicePrincipalId"  
        Return $servicePrincipalId
    }
    Else
    {
        Throw "Synchronization Job Id '$Id' not found."
    }
}

Function Get-AADCloudSyncToolsCurrentDateTimeString
{
    Return (Get-Date).tostring("yyyyMMdd-hhmmss")
}

Function Compress-AADCloudSyncToolsAgentLogFiles
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Source,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $Target,

        [Parameter(Position = 2, Mandatory = $true)]
        [string] $DateTimeString

    )
    [string] $zipFileTarget = "AADCloudProvisioningDiagnostics-$DateTimeString"
    [string] $zipPathTarget = Join-Path -Path $Target -ChildPath "$zipFileTarget.zip"
    [string] $tempFolder    = Join-Path -Path $env:temp -ChildPath $zipFileTarget

    Write-Verbose "Source        = $Source"
    Write-Verbose "Target        = $Target"
    Write-Verbose "DateTimeString= $DateTimeString"
    Write-Verbose "zipFileTarget = $zipFileTarget"
    Write-Verbose "zipPathTarget = $zipPathTarget"
    Write-Verbose "tempFolder    = $tempFolder"

    # Copy all files to %Temp% folder in case there are being used by another process
    Try  
    {
        Write-Verbose "Copying all files from '$Source' to '$tempFolder'..."
        Copy-Item $Source $tempFolder -Recurse -ErrorAction Stop
    }
    Catch   
    {
        Throw "Unable to copy files to Temp Folder. Error Details: $($_.Exception.Message)"
    }

    # Compress AAD Connect Diagnostics folder
    Try
    {
        Write-Verbose "Compressing all files from '$tempFolder' to '$zipPathTarget'..."
        Add-Type -AssemblyName "System.io.Compression.Filesystem"
        [io.Compression.Zipfile]::CreateFromDirectory($tempFolder, $zipPathTarget)
        
        Write-Host "Azure AD Cloud Sync Diagnostics saved in: `n$zipPathTarget `n" -ForegroundColor Green
    }
    Catch
    {
        Throw "Unable to compress files from Temp Folder. Error Details: $($_.Exception.Message)"
    }
    Remove-Item -Path $tempFolder -Recurse -Force

}

Function ExportEventViewer
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $TargetPath,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $EventViewerLog
    )
    
    # Export Windows Event Logs
    $after = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
    $query = "/q:*[System[TimeCreated[@SystemTime>='$($after)T00:00:00.000Z']]]"  
    Write-Verbose "Exporting Event Viewer logs from $EventViewerLog to $TargetPath. Query: $query"
    wevtutil epl $EventViewerLog $TargetPath $query "/ow:true"
}

Function Export-AADCloudSyncToolsEventViewerLogs
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Target,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $DateTimeString
    )

    [string] $evtName = 'Application'
    [string] $evtTarget = Join-Path -Path $Target -ChildPath "AADCloudProvisioningDiagnostics-$DateTimeString-$evtName.evtx"
    ExportEventViewer -TargetPath $evtTarget -EventViewerLog $evtName

    [string] $evtName = 'System'
    [string] $evtTarget = Join-Path -Path $Target -ChildPath "AADCloudProvisioningDiagnostics-$DateTimeString-$evtName.evtx"
    ExportEventViewer -TargetPath $evtTarget -EventViewerLog $evtName

    #[string] $evtName = 'AgentUpdater'
    #[string] $evtLogName = 'Microsoft-AzureADConnect-AgentUpdater/Admin'
    #[string] $evtTarget = Join-Path -Path $Target -ChildPath "AADCloudProvisioningDiagnostics-$DateTimeString-$evtName.evtx"
    #ExportEventViewer -TargetPath $evtTarget -EventViewerLog $evtLogName

    [string] $evtName = 'ProvisioningAgent'
    [string] $evtLogName = 'Microsoft-AzureADConnect-ProvisioningAgent/Admin'
    [string] $evtTarget = Join-Path -Path $Target -ChildPath "AADCloudProvisioningDiagnostics-$DateTimeString-$evtName.evtx"
    ExportEventViewer -TargetPath $evtTarget -EventViewerLog $evtLogName
}

Function Remove-AADCloudSyncToolsUser
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $ObjectId
    
    )
    
    Write-Verbose "Removing current Sync Service Account (ObjectId: $ObjectId)..." 
    $method = "DELETE"
    $uri = "https://graph.microsoft.com/beta/users/$ObjectId"
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method
}

Function Get-AADCloudSyncToolsServicePrincipalSecrets
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $ServicePrincipalId    
    )

    # Read secrets
    $uri = "https://graph.microsoft.com/beta/servicePrincipals/$ServicePrincipalId/synchronization/secrets"
    $method = 'GET'
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
    Return $response
}

Function Compare-AADCloudSyncToolsServicePrincipalSecrets
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        $ReferenceObject,

        [Parameter(Position = 0, Mandatory = $true)]
        [string] $ServicePrincipalId

    )

    # Read secrets from Service Principal
    $response = Get-AADCloudSyncToolsServicePrincipalSecrets -ServicePrincipalId $ServicePrincipalId

    # Compare Service Principal secrets with ReferenceObject
    $responseJson = $response.QueryResults | ConvertFrom-Json
    $responseValue = $responseJson.value
    Write-Verbose "Current Azure AD Cloud Sync Service Account secrets: '$responseValue'"
    $objDiff = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $responseValue
    
    # Return
    If ($objDiff -eq $null)
    {
        Return $true
    }
    Else
    {
        Return $false
    }
}

Function Clear-AADCloudSyncToolsServicePrincipalSecrets
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $ServicePrincipalId    
    )

    # Read secrets from Service Principal
    $response = Get-AADCloudSyncToolsServicePrincipalSecrets -ServicePrincipalId $ServicePrincipalId
    $responseJson = $response.QueryResults | ConvertFrom-Json
    $secrets = @($responseJson.value)

    If ($secrets.Count -gt 0)
    {

        # Clear all secrets in Service Principal
        Write-Host "Cleaning Azure AD Cloud Sync Service Principal secrets..." -ForegroundColor Cyan

        ForEach ($keyValuePair in $secrets)
        {
            $keyValuePair.value = ""
        }

        $cleanSecretsJson = $secrets | ConvertTo-Json -Compress
        $cleanSecrets = $cleanSecretsJson.ToString()
        $cleanSecrets = '{"value":' + $cleanSecrets + '}'
        $uri = "https://graph.microsoft.com/beta/servicePrincipals/$ServicePrincipalId/synchronization/secrets"
        $method = 'PUT'
        $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body $cleanSecrets

        # Wait until change is replicated and confirm clearedSecretsValue
        $clearedSecretsValue = "[]" |  ConvertFrom-Json
        $keepWaiting = $true
        $retries = 0
        Do
        {
            If ($retries -ge $script:AADCloudSyncTools.MaxRetries)
            {
                Throw "Timed out cleaning Azure AD Cloud Sync Service Principal secrets."
            }

            # Delay 
            Write-Verbose "Waiting $($script:AADCloudSyncTools.ReplicationDelay) seconds for Azure AD replication..."
            Start-Sleep -Seconds $script:AADCloudSyncTools.ReplicationDelay
            $retries++
        
            # If current Secrets are equal to cleared secrets then secrets are cleared
            If (Compare-AADCloudSyncToolsServicePrincipalSecrets -ReferenceObject $clearedSecretsValue -ServicePrincipalId $syncSrvPrincipalId)
            {
                $keepWaiting = $false
            }
            Else 
            {
                Write-Verbose "Azure AD Cloud Sync Service Principal secrets not cleared yet. Retry $retries of $($script:AADCloudSyncTools.MaxRetries)..."
            }
        }
        While ($keepWaiting)
        Write-verbose "Azure AD Cloud Sync Service Principal secrets cleared successfully."
    }
    Else
    {
        Write-verbose "Azure AD Cloud Sync Service Principal secrets were clean."
    }
}

Function Reset-AADCloudSyncToolsServicePrincipalSecrets
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $ServicePrincipalId    
    )

    # Insert AppKey secrets to re-create AD2AADProvisioning Sync Account
    Write-Host "Repairing Azure AD Cloud Sync Service Account..." -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/beta/servicePrincipals/$ServicePrincipalId/synchronization/secrets"
    $method = 'PUT'
    $json = "{""value"":[{""key"":""AppKey"",""value"":""{\""appKeyScenario\"":\""AD2AADProvisioning\""}""}]}"
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body $json
    $clearedSecretsValue = "[]" |  ConvertFrom-Json

    # Wait until change is replicated
    $keepWaiting = $true
    $retries = 0
    Do
    {
        If ($retries -ge $script:AADCloudSyncTools.MaxRetries)
        {
            Throw "Time out while repairing Azure AD Cloud Sync Service Account."
        }

        # Delay 
        Write-Verbose "Waiting $($script:AADCloudSyncTools.ReplicationDelay) seconds for Azure AD replication..."
        Start-Sleep -Seconds $script:AADCloudSyncTools.ReplicationDelay
        $retries++
        
        # If current Secrets are different than cleared secrets then secrets are repaired
        If (Compare-AADCloudSyncToolsServicePrincipalSecrets -ReferenceObject $clearedSecretsValue -ServicePrincipalId $syncSrvPrincipalId)
        {
            Write-Verbose "Azure AD Cloud Sync Service Account not repaired yet. Retry $retries of $($script:AADCloudSyncTools.MaxRetries)..."
        }
        Else 
        {
            $keepWaiting = $false
        }

    }
    While ($keepWaiting)
}

Function Get-AADCloudSyncToolsNextPage
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Uri,
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable] $Header = $null)
  
    IsAADCloudSyncToolsConnected

    If ($Header -eq $null)
    {
        $Header = $script:AADCloudSyncTools.Header
    }
    Else
    {
        $Header += $script:AADCloudSyncTools.Header
    }

    If ($Uri -eq $null -Or $Uri -like '')
    {
        Return $null
    }

    $method = 'GET'
    $response = Invoke-AADCloudSyncToolsGraphQuery -Header $Header -Method $method -Uri $Uri -FetchAllPages $false
    $queryResultsJson = $response.QueryResults | ConvertFrom-Json

    If ($response.StatusCode -eq 200)
    {
        Return $queryResultsJson
    }
    Else
    {
        Return $null
    }
}

Function Get-AADCloudSyncToolsGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [string] $ObjectId = $null)

    IsAADCloudSyncToolsConnected

    Write-Verbose "Searching for Azure AD Cloud Sync Groups..."

    $method = "GET"
    $uri = "https://graph.microsoft.com/beta/groups/"
    if ($ObjectId -ne $null)
    {
        $uri += "/" + $ObjectId
    }
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
    $queryResultsJson = $response.QueryResults | ConvertFrom-Json

    $statusCode = $response.StatusCode

    If ($statusCode -eq 200)
    {
        Return $queryResultsJson 
    }
    Else
    {
        Return $null
    }
}

Function Get-AADCloudSyncToolsGroupMembers
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ObjectId,
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]$Header=$null)

    IsAADCloudSyncToolsConnected
    
    If ($Header -eq $null)
    {
        $Header = $script:AADCloudSyncTools.Header
    }
    Else
    {
        $Header += $script:AADCloudSyncTools.Header
    }

    $uri = ("https://graph.microsoft.com/beta/groups/" + $ObjectId + "/members?`$count=true")
    $method = 'GET'
    $response = Invoke-AADCloudSyncToolsGraphQuery -Header $Header -Method $method -Uri $uri -FetchAllPages $false
    $queryResultsJson = $response.QueryResults | ConvertFrom-Json

    If ($response.StatusCode -eq 200)
    {
        Return $queryResultsJson
    }
    Else
    {
        Return $null
    }
}
#endregion
#=======================================================================================


#=======================================================================================
#region Module Cmdlets
#=======================================================================================

<#
.Synopsis
   Install AADCloudSyncTools prerequisites
.DESCRIPTION
   Checks for the presence of PowerShellGet v2.2.4.1 or later and Azure AD and MSAL.PS modules and installs these if missing.
.EXAMPLE
   Install-AADCloudSyncToolsPrerequisites
#>
Function Install-AADCloudSyncToolsPrerequisites
{
    [CmdletBinding()]
    Param ()

    # PowerShellGet Module
    $powerShellGetModule = @(Get-Module PowerShellGet -ListAvailable)
    $powerShellGetInstalled = $false
    [version] $minVersion = ('{0}.{1}.{2}.{3}' -f "2.2.4.1".split('.'))
    ForEach ($m in $powerShellGetModule)
    {
        Write-Verbose "PowerShellGet current version: $($m.Version) | PowerShellGet minimum version: $minVersion"
        If ($m.Version -ge $minVersion)
        {
            $powerShellGetInstalled = $true
            Write-Verbose "PowerShellGet module is already installed."
        }
    }

    If (-not $powerShellGetInstalled)
    {
        IsPowerShellSessionElevated
        Write-Host "Installing 'PowerShellGet' Module. Please wait..." -ForegroundColor Cyan
        Try
        {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-Module PowerShellGet -Force -ErrorAction Stop
        }
        Catch
        {
            Throw "There was a problem installing 'PowerShellGet' Module. Error Details: $($_.Exception.Message)"
        }
        Write-Warning "'PowerShellGet' Module installed successfully. Close this PowerShell window and run 'Install-AADCloudSyncToolsPrerequisites' again."
        Return
    }

    # MSAL.PS Module
    $msalModule = @(Get-Module MSAL.PS -ListAvailable)
    Write-Verbose "MSAL.PS module installed: $($msalModule.Count -gt 0)"
    If ($msalModule.Count -eq 0)
    {
        IsPowerShellSessionElevated
        Write-Host "Installing 'MSAL.PS' Module. Please wait..." -ForegroundColor Cyan
        Try
        {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-Module MSAL.PS -Force -AcceptLicense -ErrorAction Stop
        }
        Catch
        {
            Throw "There was a problem installing 'MSAL.PS' Module. Error Details: $($_.Exception.Message)"
        }
    }

    # Azure AD Module
    $aadModule = @(Get-Module AzureAD* -ListAvailable)
    Write-Verbose "AzureAD module installed: $($msalModule.Count -gt 0)"
    If ($aadModule.Count -eq 0)
    {
        IsPowerShellSessionElevated
        Write-Host "Installing 'AzureAD' Module. Please wait..." -ForegroundColor Cyan
        Try
        {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Install-Module AzureAD -Force -ErrorAction Stop
        }
        Catch
        {
            Throw "There was a problem installing 'AzureAD' module. Error Details: $($_.Exception.Message)"
        }
    }
    Write-Host "All AADCloudSyncTools prerequisites installed successfully." -ForegroundColor Green
}

<#
.Synopsis
   Sets the target TenantId for AADCloudSyncTools operations
.DESCRIPTION
   This can be used when the Cloud Sync Agent is not currently installed or it is installed but you want to target a different 
   Azure AD tenant than the one Cloud Sync Agent is using. 
   The TenantId set with this function will only persist during the PowerShell session and you'll need to call this function 
   before using Connect-AADCloudSyncTools.
.EXAMPLE
   Set-AADCloudSyncToolsTenantId -TenantId 6cd90596-1dc4-4f11-90de-7fafcc2aef10
#>
Function Set-AADCloudSyncToolsTenantId
{
    [CmdletBinding()]
    Param 
    (     
        [parameter(Mandatory = $true)] 
        [guid] $TenantId
    )

    [string] $script:AADCloudSyncTools.TenantId = $TenantId.ToString()
}

<#
.Synopsis
   Connects AADCloudSyncTools to AzureAD
.DESCRIPTION
   Uses AzureAD module to connect to Azure AD and the MSAL.PS module to request a token for Microsoft Graph
.EXAMPLE
   Connect-AADCloudSyncTools
.EXAMPLE
   Connect-AADCloudSyncTools -Credentials $creds
.EXAMPLE
   Connect-AADCloudSyncTools -LoginHint Admin@Contoso.onmicrosoft.com
#>
Function Connect-AADCloudSyncTools 
{
    [CmdletBinding()]
    Param 
    (     
        [parameter(Mandatory = $false)] 
        [string] $LoginHint,
        [parameter(Mandatory = $false)]
        [switch] $DeviceLogin
    )
    
    IsPowerShellModulePresent -ModuleName 'MSAL.PS'

    if (-not (IsTenantIdPresent))
    {
        InitInternalModuleVariables
    }

    # Obtain access token for Ms Graph
    Try
    {
        if ($DeviceLogin) {
            Write-Host "`nConnecting to Microsoft Graph using device login (non-interactive)...`n"
            Write-Verbose "Connecting to TenantId: $($script:AADCloudSyncTools.TenantId) | ClientId: $($script:AADCloudSyncTools.ClientId) | DeviceLogin: $DeviceLogin"
            $script:AADCloudSyncTools.AccessToken = Get-MsalToken -ClientId $script:AADCloudSyncTools.ClientId -TenantId $script:AADCloudSyncTools.TenantId -DeviceCode -ErrorAction Stop
        }
        elseif ($LoginHint -like "")
        {
            Write-Host "`nConnecting to Microsoft Graph...`n"
            Write-Verbose "Connecting to TenantId: $($script:AADCloudSyncTools.TenantId) | ClientId: $($script:AADCloudSyncTools.ClientId)"
            $script:AADCloudSyncTools.AccessToken = Get-MsalToken -ClientId $script:AADCloudSyncTools.ClientId -TenantId $script:AADCloudSyncTools.TenantId -DeviceCode -ErrorAction Stop
        }
        else
        {
            Write-Host "`nConnecting user '$LoginHint' to Microsoft Graph...`n" -ForegroundColor Cyan
            Write-Verbose "Connecting to TenantId: $($script:AADCloudSyncTools.TenantId) | ClientId: $($script:AADCloudSyncTools.ClientId) | LoginId: $LoginHint"
            $script:AADCloudSyncTools.AccessToken = Get-MsalToken -ClientId $script:AADCloudSyncTools.ClientId -TenantId $script:AADCloudSyncTools.TenantId -LoginHint $LoginHint -Interactive -ErrorAction Stop
        }   
    }
    Catch
    {
        Throw "There was a problem requesting an access token. Error Details: $($_.Exception.Message)"
    }

    $script:AADCloudSyncTools.Username = $script:AADCloudSyncTools.AccessToken.Account.Username
    $homeTenant = $script:AADCloudSyncTools.AccessToken.Account.HomeAccountId.TenantId
    If ($homeTenant -ne $script:AADCloudSyncTools.TenantId)
    {
        Throw "User account '$($script:AADCloudSyncTools.Username)' does not belong to the Azure AD Cloud Sync Agent's tenant '$($script:AADCloudSyncTools.TenantId)'. To use a different tenant please call 'Set-AADCloudSyncToolsTenantId' first."
    }
    
    $script:AADCloudSyncTools.Connected = $true
    Write-Verbose "Connected = $($script:AADCloudSyncTools.Connected) with Username: $($script:AADCloudSyncTools.Username)"
    Write-Host -ForegroundColor:Green "TenantId: '$($script:AADCloudSyncTools.TenantId)' `n`nConnected with '$($script:AADCloudSyncTools.Username)' to Azure AD successfully. `n"
}

<#
.Synopsis
   Show AADCloudSyncTools information
.DESCRIPTION
   Shows Azure AD Tenant details and internal variables state
.EXAMPLE
   Get-AADCloudSyncToolsConnection
#>
Function Get-AADCloudSyncToolsInfo
{
    $script:AADCloudSyncTools
}

<#
.Synopsis
   Makes a query to Microsoft Graph
.DESCRIPTION
   Invokes a Web request for the URI, Method and Body specified as parameters
.EXAMPLE
   Invoke-AADCloudSyncToolsGraphQuery -Uri "https://graph.microsoft.com/beta/servicePrincipals" -Method GET -Body ""
#>
Function Invoke-AADCloudSyncToolsGraphQuery
{
    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $true)] 
        [string] $Uri,
        [parameter(Mandatory = $true)] 
        [string] $Method,
        [parameter(Mandatory = $false)] 
        [string] $Body,
        [parameter(Mandatory = $false)] 
        [System.Collections.Hashtable] $Header = $null,
        [parameter(Mandatory = $false)] 
        [bool] $FetchAllPages = $true
    )

    IsAADCloudSyncToolsConnected

    Request-AADCloudSyncToolsRefreshToken

    If ($Header -eq $null)
    {
        $Header = $script:AADCloudSyncTools.Header
    }

    # Create return object    
    $queryResult = New-Object PSObject -Property @{StatusCode = ""; QueryResults = @()}

    Try 
    {
        If ($Method -eq 'GET' -or $Method -eq 'DELETE')
        {
            Do
            {
                # Invoke Query
                Write-Verbose "Calling Microsoft Graph - Invoking Web Request: $Method | $Uri"
                $response =  Invoke-WebRequest -Headers $Header -Uri $Uri -UseBasicParsing -Method $Method -ContentType "application/json"
                If ($response.Content.value -ne $null)
                {
                    $queryResult.QueryResults += $response.Content.value
                }
                Else
                {
                    $queryResult.QueryResults += $response.Content
                }

                $queryResult.StatusCode = $response.StatusCode
                $responseContent = $response.Content | ConvertFrom-Json
                $Uri = $responseContent.'@odata.nextLink'
                Write-Verbose "Returned Status Code : $($queryResult.StatusCode) | More: $(-not (($Uri -eq $null) -or ($Uri -like '')))"
                Write-Verbose "Returned Query Result: $($response.QueryResults)"
                If ($FetchAllPages -eq $false)
                {
                    Return $queryResult
                }
            }
            Until (($Uri -eq $null) -or ($Uri -like ''))
        }

        If (($Method -eq 'PATCH') -or ($Method -eq 'POST') -or ($Method -eq 'PUT'))
        {
            # Body Verbose output
            If ($Body.length -gt 1024)
            {
                $bodyTrimmed = $Body.SubString(0,1024)
                $bodyTrimmed += "..."
            }
            Else
            {
                $bodyTrimmed = $Body
            }

            # Invoke Query
            Write-Verbose "Calling Microsoft Graph - Invoking Web Request: $Method | $Uri | $bodyTrimmed"
            $response =  Invoke-WebRequest -Headers $Header -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -UseBasicParsing
            If ($response.Content.value -ne $null)
            {
                $queryResult.QueryResults += $response.Content.value
            }
            Else
            {
                $queryResult.QueryResults += $response.Content
            }

            $queryResult.StatusCode = $response.StatusCode
            Write-Verbose "Returned Status Code: $($response.StatusCode)"
            Write-Verbose "Returned Query Result: $($response.QueryResults)"
        }
    }
    Catch 
    {
        # Output exception details from Response
        Write-Verbose "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Verbose "Status Description: $($_.Exception.Response.StatusDescription)"
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Error "$Method $Uri | Response: `n$responseBody"
        
        # Create query response
        $queryResult.QueryResults += $responseBody
        $queryResult.StatusCode = $_.Exception.Response.StatusCode.value__
    }
    Return $queryResult
}

<#
.Synopsis
   Returns the Service Principal(s) for Azure AD Cloud Sync  
.DESCRIPTION
   Uses Graph to get the Service Principal(s) for AD2AAD and/or SyncFabric. Without paramaters, will only return AD2AAD Service Principal(s).
.EXAMPLE
   Get-AADCloudSyncToolsServicePrincipal
.EXAMPLE
   Get-AADCloudSyncToolsServicePrincipal -ServicePrincipal SyncFabric
#>
Function Get-AADCloudSyncToolsServicePrincipal
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("CloudSync", "SyncFabric", "All")]
        [string] $ServicePrincipal = "SyncFabric"
    )

    IsAADCloudSyncToolsConnected

    # Set the Ms Graph query filter
    switch ($ServicePrincipal)
    {
        'CloudSync' 
            {
                $filter = "?filter=applicationTemplateId eq '1a4721b3-e57f-4451-ae87-ef078703ec94'"
            }
        'SyncFabric' 
            {
                $filter = "?filter=startswith(DisplayName,'Microsoft.Azure.SyncFabric')"
            }
        Default 
            {
                $filter = ''
            }
    }

    # Search for Azure AD Cloud Sync Service Principals
    Write-Verbose "Searching for $ServicePrincipal Service Principal(s)..."
    $uri = "https://graph.microsoft.com/beta/servicePrincipals"
    $method = 'GET'
    $queryResult = Invoke-AADCloudSyncToolsGraphQuery -Method $method -Uri $uri$filter

    # Parse all results
    $resultsJson = @($queryResult.QueryResults)
    Write-Verbose "Returned $($resultsJson.Count) pages."

    $results = @()
    ForEach ($rJson in $resultsJson)
    {
        $r = $rJson | ConvertFrom-Json
        $results += $r.value

    }
    Write-Verbose "Returned $($results.Count) total results."
    
    # Return results
    If ($results.Count -gt 0)
    {
        Write-Verbose "Returning $ServicePrincipal Service Principal(s)..."
        Return $results
    }
    Else
    {
        Throw "$ServicePrincipal Service Principal not found."
    }
}

<#
.Synopsis
   Returns Azure AD Cloud Sync Job(s)
.DESCRIPTION
   Uses Graph to get AD2AAD Service Principals and returns the Synchronization Job information. Can be also called using the specific Sync Job Id as a parameter.
.EXAMPLE
   Get-AADCloudSyncToolsJob
.EXAMPLE
   Get-AADCloudSyncToolsJob -JobTemplate AD2AADProvisioning
.EXAMPLE
   Get-AADCloudSyncToolsJob -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Get-AADCloudSyncToolsJob
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "JobTemplate")]
        [ValidateSet("AD2AADProvisioning", "AD2AADPasswordHash", "All")]
        [string] 
        $JobTemplate = "All",
        
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "JobId")]
        [string]
        $Id,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = "JobTemplate")]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = "JobId")]
        [switch]
        $RawData
    )

    IsAADCloudSyncToolsConnected

    Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName) | JobTemplate: $JobTemplate | Id: $id | RawData: $($RawData.IsPresent)"    
    Write-Verbose "Searching for Azure AD Cloud Sync Service Principals..."
    $Ad2AadSrvPrincipal = @(Get-AADCloudSyncToolsServicePrincipal -ServicePrincipal CloudSync)

    # Parse Query Results
    Write-Verbose "Retrieving Azure AD Cloud Sync Job(s)..."
    $results = @()
    ForEach ($sp in $Ad2AadSrvPrincipal)
    {
        $resultsJson = $()
        $method = "GET"
        $uri = "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/synchronization/jobs"
        $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
        $queryResultsJson = $response.QueryResults | ConvertFrom-Json
        Write-Verbose "Returned Synchronization Job(s) for $($queryResultsJson.'@odata.context'):"

        # Get query results value - Filter by JobId or JobTemplate
        $queryResults = $null
        if ($PSCmdlet.ParameterSetName -eq "JobId")
        {
            Write-Verbose "Returning results based on Job Id: $Id"
            $queryResults = $queryResultsJson.value | where {$_.id -eq $Id}
        }
        ElseIf ($JobTemplate -ne "All")
        {
            Write-Verbose "Returning results based on Job Template: $JobTemplate"
            $queryResults = $queryResultsJson.value | where {$_.templateId -eq $JobTemplate}
        }
        Else
        {
            Write-Verbose "Returning results for all Sync Jobs"
            $queryResults = $queryResultsJson.value
        }

        if ($queryResults -ne $null)
        {
            # Add the returned query '@odata.context' to the query results object
            ForEach ($r in $queryResults)
            {
                Add-Member -InputObject $r -MemberType NoteProperty -Name '@odata.context' -Value $($queryResultsJson.'@odata.context') -Force
                Add-Member -InputObject $r -MemberType NoteProperty -Name 'servicePrincipalId' -Value $($sp.id) -Force
            }
            $results += $queryResults
            if ($PSCmdlet.ParameterSetName -eq "JobId")
            {
                break
            }
        }
    }

    # Return results
    If ($results.Count -gt 0)
    {
        If ($RawData.IsPresent)
        {
            Write-Verbose "Exit Get-AADCloudSyncToolsJob Count: $($results.Count)"
            Return $results
        }
        Else
        {
            $syncJobResults = @()
            ForEach ($r in $results)
            {
                $syncJobResults += $r | Select id, templateId, servicePrincipalId
            }
            Write-Verbose "Exit Get-AADCloudSyncToolsJob Count: $($syncJobResults.Count)"
            Return $syncJobResults
        }
    }
}

<#
.Synopsis
   Returns Azure AD Cloud Sync Job's Schedule
.DESCRIPTION
   Uses Graph to get AD2AAD Service Principals and returns the Synchronization Job's Schedule. Can be also called using the specific Sync Job Id as a parameter.
.EXAMPLE
   Get-AADCloudSyncToolsJobSchedule
.EXAMPLE
   Get-AADCloudSyncToolsJobSchedule -JobTemplate AD2AADProvisioning
.EXAMPLE
   Get-AADCloudSyncToolsJobSchedule -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Get-AADCloudSyncToolsJobSchedule
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "JobTemplate")]
        [ValidateSet("AD2AADProvisioning", "AD2AADPasswordHash", "All")]
        [string] 
        $JobTemplate = "All",
        
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "JobId")]
        [string]
        $Id
    )

    IsAADCloudSyncToolsConnected

    # Check ParameterSets
    Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName) | JobTemplate: $JobTemplate | Id: $id"    
    if ($PSCmdlet.ParameterSetName -eq "JobTemplate")
    {
        $results = @(Get-AADCloudSyncToolsJob -JobTemplate $JobTemplate -RawData)
    }
    Else
    {
        $results = @(Get-AADCloudSyncToolsJob -Id $Id -RawData)
    }

    $scheduleResults = @()
    Write-Verbose "Entering Get-AADCloudSyncToolsJobSchedule Count: $($results.Count)"
    If ($results.Count -gt 0)
    {
        
        ForEach ($r in $results)
        {
            $scheduleObj = "" | Select id
            $scheduleObj.id = $r.id
            $schedulePropList = Get-member -InputObject $r.schedule -MemberType NoteProperty
            ForEach ($property in $schedulePropList)
            {
                $propName = $property.Name
                if ($propName -eq 'interval')
                {
                    # Try convert iso-8601-duration to minutes
                    Try
                    {
                        $propValue = [System.Xml.XmlConvert]::ToTimeSpan($r.schedule.$propName).TotalMinutes
                    }
                    Catch
                    {
                        $propValue = $r.schedule.$propName
                    }
                    $propName = 'intervalMins'
                }
                Else
                {
                    $propValue = $r.schedule.$propName
                }
                Write-Verbose "Adding -Name $propName -Value $propValue"
                Add-Member -InputObject $scheduleObj -MemberType NoteProperty -Name $propName -Value $propValue -Force
            }
            $scheduleResults +=  $scheduleObj
        }
        Return $scheduleResults
    }

}

<#
.Synopsis
   Returns Azure AD Cloud Sync Job's Status
.DESCRIPTION
   Uses Graph to get AD2AAD Service Principals and returns the Synchronization Job's Status. Can be also called using the specific Sync Job Id as a parameter.
.EXAMPLE
   Get-AADCloudSyncToolsJobStatus
.EXAMPLE
   Get-AADCloudSyncToolsJobStatus -JobTemplate AD2AADProvisioning
.EXAMPLE
   Get-AADCloudSyncToolsJobStatus -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Get-AADCloudSyncToolsJobStatus
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "JobTemplate")]
        [ValidateSet("AD2AADProvisioning", "AD2AADPasswordHash", "All")]
        [string] 
        $JobTemplate = "All",
        
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "JobId")]
        [string]
        $Id
    )

    IsAADCloudSyncToolsConnected

    Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName) | JobTemplate: $JobTemplate | Id: $id"    

    if ($PSCmdlet.ParameterSetName -eq "JobTemplate")
    {
        $results = @(Get-AADCloudSyncToolsJob -JobTemplate $JobTemplate -RawData)
    }
    Else
    {
        $results = @(Get-AADCloudSyncToolsJob -Id $Id -RawData)
    }

    $statusResults = @()
    Write-Verbose "Entering Get-AADCloudSyncToolsJobStatus Count: $($results.Count)"
    If ($results.Count -gt 0)
    {
        # Craft a response object and flatten all hash-tables and custom objects
        ForEach ($r in $results)
        {
            # Include sync job id
            $statusObj = "" | Select id
            $statusObj.id = $r.id

            # Copy properties to response object
            $statusPropList = @('steadyStateFirstAchievedTime', 'steadyStateLastAchievedTime', 'countSuccessiveCompleteFailures', 'escrowsPruned', 'code', 'progress', 'troubleshootingUrl')
            ForEach ($propName in $statusPropList)
            {
                $propValue = $r.status.$propName
                Write-Verbose "Adding -Name $propName -Value $($r.status.$prop)"
                Add-Member -InputObject $statusObj -MemberType NoteProperty -Name $propName -Value $propValue -Force
            }

            # Convert quarantine
            If ($statusObj.code -eq 'Quarantine')
            {
                $quarantine = $r.status.quarantine
                $quarantinePropList = $quarantine | Get-Member -MemberType NoteProperty
                $propertyPrefix = "quarantine_"
                ForEach ($prop in $quarantinePropList) 
                {
                    $propName = $prop.Name
                    if ($propName -ne 'error')
                    {
                        $propValue = $quarantine.$propName
                        Write-Verbose "Adding -Name $($propertyPrefix + $propName) -Value $propValue"
                        Add-Member -InputObject $statusObj -MemberType NoteProperty -Name $($propertyPrefix + $propName) -Value $propValue -Force
                    }
                }
                $quarantineError = $r.status.quarantine.error
                $quarantinePropList = $quarantineError | Get-Member -MemberType NoteProperty
                $propertyPrefix = "quarantineError_"
                ForEach ($prop in $quarantinePropList) 
                {
                    $propName = $prop.Name
                    $propValue = $quarantineError.$propName
                    Write-Verbose "Adding -Name $($propertyPrefix + $propName) -Value $propValue"
                    Add-Member -InputObject $statusObj -MemberType NoteProperty -Name $($propertyPrefix + $propName) -Value $propValue -Force
                }
            }
            Else
            {
                Add-Member -InputObject $statusObj -MemberType NoteProperty -Name 'quarantine' -Value '' -Force
            }

            # Convert LastExecution
            $lastExecution = $r.status.lastExecution
            if ($lastExecution -ne $null)
            {
                $lastExecutionPropList = $lastExecution | Get-Member -MemberType NoteProperty
                $propertyPrefix = "lastRun_"
                ForEach ($prop in $lastExecutionPropList) 
                {
                    $propName = $prop.Name
                    $propValue = $lastExecution.$propName
                    Write-Verbose "Adding -Name $($propertyPrefix + $propName) -Value $propValue"
                    Add-Member -InputObject $statusObj -MemberType NoteProperty -Name $($propertyPrefix + $propName) -Value $propValue -Force
                }
            }

            # Convert LastSuccessfulExecution
            $lastSuccessfulExecution = $r.status.lastSuccessfulExecution
            if ($lastSuccessfulExecution -ne $null)
            {
                $lastSuccessfulExecutionPropList = $lastSuccessfulExecution | Get-Member -MemberType NoteProperty
                $propertyPrefix = "lastSuccessfulRun_"

                ForEach ($prop in $lastSuccessfulExecutionPropList) 
                {
                    $propName = $prop.Name
                    $propValue = $lastSuccessfulExecution.$propName
                    Write-Verbose "Adding -Name $($propertyPrefix + $propName) -Value $propValue"
                    Add-Member -InputObject $statusObj -MemberType NoteProperty -Name $($propertyPrefix + $propName) -Value $propValue -Force
                }
            }

            # Convert SynchronizedEntryCountByType
            $syncedEntryCountByType = $r.status.synchronizedEntryCountByType

            ForEach ($row in $syncedEntryCountByType) 
            {
                $propertyName = "synchronizedCount_"
                $spaceCharI = $row.key.ToString().LastIndexOf(" ")
                if ($spaceCharI -ge 0)
                {
                    $propertyName += $row.key.ToString().Substring($spaceCharI+1)
                }
                Else
                {
                    $propertyName += $row.key.ToString()
                }
                Write-Verbose "Adding -Name $propertyName -Value $($row.value)"
                Add-Member -InputObject $statusObj -MemberType NoteProperty -Name $propertyName -Value $row.value -Force 
            }
            $statusResults += $statusObj
        }
    }
    Return $statusResults
}


<#
.Synopsis
   Returns Azure AD Cloud Sync Job's Settings
.DESCRIPTION
   Uses Graph to get AD2AAD Service Principals and returns the Synchronization Job's Settings. Can be also called using the specific Sync Job Id as a parameter.
.EXAMPLE
   Get-AADCloudSyncToolsJobSettings
.EXAMPLE
   Get-AADCloudSyncToolsJobSettings -JobTemplate AD2AADProvisioning
.EXAMPLE
   Get-AADCloudSyncToolsJobSettings -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Get-AADCloudSyncToolsJobSettings
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "JobTemplate")]
        [ValidateSet("AD2AADProvisioning", "AD2AADPasswordHash", "All")]
        [string] 
        $JobTemplate = "All",
        
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "JobId")]
        [string]
        $Id
    )

    IsAADCloudSyncToolsConnected

    Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName) | JobTemplate: $JobTemplate | Id: $id"    

    if ($PSCmdlet.ParameterSetName -eq "JobTemplate")
    {
        $results = @(Get-AADCloudSyncToolsJob -JobTemplate $JobTemplate -RawData)
    }
    Else
    {
        $results = @(Get-AADCloudSyncToolsJob -Id $Id -RawData)
    }

    $settingsResults = @()
    Write-Verbose "Entering Get-AADCloudSyncToolsJobStatus Count: $($results.Count)"
    If ($results.Count -gt 0)
    {
        # Craft a response object and flatten all hash-tables and custom objects
        ForEach ($r in $results)
        {
            # Include sync job id
            $settingsObj = "" | Select id
            $settingsObj.id = $r.id

            # Convert synchronizationJobSettings hashtable to object
            $jobSettings = $r.synchronizationJobSettings
            ForEach ($row in $jobSettings)
            {
                $propName = $row.name.ToString()
                # skip redundant Domain information
                if ($propName -ne 'Domain')
                {            
                    $propValue = $row.value.ToString()
                    Write-Verbose "Adding -Name $propName -Value $propValue"
                    Add-Member -InputObject $settingsObj -MemberType NoteProperty -Name $propName -Value $propValue -Force 
                }
            }
            $settingsResults += $settingsObj
        }
    }
    Return $settingsResults
}

<#
.Synopsis
   Returns Azure AD Cloud Sync Job's Schema
.DESCRIPTION
   Uses Graph to get AD2AAD Service Principals and returns the Synchronization Job's Schema.
.EXAMPLE
   Get-AADCloudSyncToolsJobSettings -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Get-AADCloudSyncToolsJobSchema
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $Id
    )

    IsAADCloudSyncToolsConnected

    Write-Verbose "Searching for Azure AD Cloud Sync Service Principals..."
    $Ad2AadSrvPrincipal = @(Get-AADCloudSyncToolsServicePrincipal -ServicePrincipal CloudSync)

    # Parse Query Results
    Write-Verbose "Retrieving Azure AD Cloud Sync Job(s)..."
    ForEach ($sp in $Ad2AadSrvPrincipal)
    {
        $resultsJson = $()
        $method = "GET"
        $uri = "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/synchronization/jobs"
        $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
        $queryResultsJson = $response.QueryResults | ConvertFrom-Json
        Write-Verbose "Returned Synchronization Job(s) for $($queryResultsJson.'@odata.context'):"

        # Get query results value - Filter by JobId
        Write-Verbose "Returning results based on Job Id: $Id"
        $queryResults = $queryResultsJson.value | where {$_.id -eq $Id}

        if ($queryResults -ne $null)
        {
            $resultsJson = $()
            $method = "GET"
            $uri = "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/synchronization/jobs/$($queryResults.id)/Schema"
            $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
            $schemaResultsJson = $response.QueryResults | ConvertFrom-Json
            break
        }
    }
    Return $schemaResultsJson
}

<#
.Synopsis
   Returns Azure AD Cloud Sync Job's Schema
.DESCRIPTION
   Uses Graph to get AD2AAD Service Principals and returns the Synchronization Job's Schema.
.EXAMPLE
   Get-AADCloudSyncToolsJobSettings -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Set-AADCloudSyncToolsJobSchema
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Id, 
        
        [Parameter(Position = 1, Mandatory = $true)]
        [string] $schema

    )

    IsAADCloudSyncToolsConnected

    Write-Verbose "Searching for Azure AD Cloud Sync Service Principals..."
    $Ad2AadSrvPrincipal = @(Get-AADCloudSyncToolsServicePrincipal -ServicePrincipal CloudSync)

    # Parse Query Results
    Write-Verbose "Retrieving Azure AD Cloud Sync Job(s)..."
    ForEach ($sp in $Ad2AadSrvPrincipal)
    {
        $resultsJson = $()
        $method = "GET"
        $uri = "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/synchronization/jobs"
        $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
        $queryResultsJson = $response.QueryResults | ConvertFrom-Json
        Write-Verbose "Returned Synchronization Job(s) for $($queryResultsJson.'@odata.context'):"

        # Get query results value - Filter by JobId
        Write-Verbose "Returning results based on Job Id: $Id"
        $queryResults = $queryResultsJson.value | where {$_.id -eq $Id}

        if ($queryResults -ne $null)
        {
            $resultsJson = $()
            $method = 'PUT'
            $uri = "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/synchronization/jobs/$($queryResults.id)/Schema"
            $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body $schema
            $schemaResultsJson = $response.QueryResults | ConvertFrom-Json
            break
        }
    }
    Return $schemaResultsJson
}


<#
.Synopsis
   Returns Azure AD Cloud Sync Job's Scope
.DESCRIPTION
   Uses Graph to get the Synchronization Job's Schema for the provided Sync Job Id and outputs all filter group's scopes.
.EXAMPLE
   Get-AADCloudSyncToolsJobScope -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481 -ObjectType 'User'
#>
Function Get-AADCloudSyncToolsJobScope
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $Id,

        [Parameter(Position = 1, Mandatory = $false)]
        [ValidateSet("User", "Group", "Contact", "InetOrgPerson", "All")]
        $ObjectType = 'All'
    )

    IsAADCloudSyncToolsConnected

    $schema = Get-AADCloudSyncToolsJobSchema -Id $Id
    if ($ObjectType -eq 'All')
    {
        $objectMapping = $schema.synchronizationRules[0].objectMappings
    }
    Else
    {
        $objectMapping = $schema.synchronizationRules[0].objectMappings | where {$_.sourceObjectName -eq $ObjectType}
    }

    if ($objectMapping -ne $null)
    {
        $scopeInputFilterGroups = $objectMapping.scope.inputFilterGroups

        $results = @()
        ForEach ($filterGroup in $scopeInputFilterGroups)
        {
            ForEach ($clause in $filterGroup.clauses)
            {
                $r = "" | select SourceOperand, Operator, TargetOperand, FilterGroup
                $r.FilterGroup = $filterGroup.Name
                $r.SourceOperand = $clause.sourceOperandName
                $r.Operator = $clause.operatorName
                
                # Concatenate all values separated by semi-colons
                $r.TargetOperand = ""
                ForEach($v in $clause.targetOperand.values)
                {
                    $r.TargetOperand += $v.ToString() + "; "
                }
                if ($r.TargetOperand -ne "")
                {
                    # remove the last semi-colon
                    $r.TargetOperand = $r.TargetOperand.Substring(0, $r.TargetOperand.LastIndexOf(';'))
                }
                $results += $r
            }
        }
    }
    $results | sort SourceOperand
}

<#
.Synopsis
   Returns the Azure AD Cloud Sync Service Account
.DESCRIPTION
   Uses Azure AD PowerShell to delete the current account (if present) and resets the Sync Account authentication with a new synchronization account in Azure AD.
.EXAMPLE
   Get-AADCloudSyncToolsServiceAccount
#>
Function Get-AADCloudSyncToolsServiceAccount
{
    [CmdletBinding()]
    Param ()

    $method = "GET"
    $uri = "https://graph.microsoft.com/beta/users?`$filter=startswith(userPrincipalName,'ADtoAADSyncServiceAccount@')"
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
    $queryResultsJson = $response.QueryResults | ConvertFrom-Json

    If ($queryResultsJson.value.Count -gt 0)
    {
        Return $queryResultsJson.value | Select-Object -First 1
    }
    Else
    {
        Return $null
    }
}

<#
.Synopsis
   Repairs Azure AD Cloud Sync Account in Azure AD
.DESCRIPTION
   Removes the current Cloud Sync Service Account (if present) and resets the service account credentials in Azure AD.
.EXAMPLE
   Repair-AADCloudSyncToolsAccount
#>
Function Repair-AADCloudSyncToolsAccount
{
    [CmdletBinding()]
    Param ()

    IsAADCloudSyncToolsConnected

    $queryResult = Get-AADCloudSyncToolsServiceAccount
    If ($queryResult -ne $null)
    {
        # Remove current ADtoAADSyncServiceAccount
        Write-Verbose "Azure AD Cloud Sync Service Account found '$($queryResult.userPrincipalName)' (ObjectId: $($queryResult.id))." 
        Remove-AADCloudSyncToolsUser $queryResult.id

        # Wait until change is replicated
        $keepWaiting = $true
        $retries = 0
        Do
        {
            If ($retries -ge $script:AADCloudSyncTools.MaxRetries)
            {
                Throw "Time out removing Azure AD Cloud Sync Service Account."
            }

            # Delay 
            Write-Verbose "Waiting $($script:AADCloudSyncTools.ReplicationDelay) seconds for Azure AD replication..."
            Start-Sleep -Seconds $script:AADCloudSyncTools.ReplicationDelay
            $retries++

            # Confirm that service account was deleted
            $queryResult = Get-AADCloudSyncToolsServiceAccount
            If ($queryResult -eq $null)
            {
                
                $keepWaiting = $false
            }
            Else
            {
                Write-Verbose "Azure AD Cloud Sync Service Account not removed yet. Retry $retries of $($script:AADCloudSyncTools.MaxRetries)..."
            }
        }
        While ($keepWaiting)
        Write-Verbose "Azure AD Cloud Sync Service Account removed successfully."
    }
    Else
    {
        # ADtoAADSyncServiceAccount not found
        Write-Verbose "Azure AD Cloud Sync Service Account not found."
    }
    
    # Get a Sync Fabric Service Principal ObjectId in the Tenant
    $syncSrvPrincipalId = (Get-AADCloudSyncToolsServicePrincipal -ServicePrincipal SyncFabric).Id

    # Check new Service Account
    $keepWaiting = $true
    $retries = 0
    Do
    {
        If ($retries -ge $script:AADCloudSyncTools.MaxRetries)
        {
            Throw "Time out checking Azure AD Cloud Sync Service Account."
        }

        # Clear secrets
        Clear-AADCloudSyncToolsServicePrincipalSecrets -ServicePrincipalId $syncSrvPrincipalId

        # Reset secrets
        Reset-AADCloudSyncToolsServicePrincipalSecrets -ServicePrincipalId $syncSrvPrincipalId

        # Delay 
        Write-Verbose "Waiting $($script:AADCloudSyncTools.ReplicationDelay) seconds for Azure AD replication..."
        Start-Sleep -Seconds $script:AADCloudSyncTools.ReplicationDelay
        $retries++

        # Confirm that service account was deleted
        $queryResult = Get-AADCloudSyncToolsServiceAccount
        If ($queryResult -ne $null)
        {
            $keepWaiting = $false
        }
        Else
        {
            Write-Verbose "Azure AD Cloud Sync Service Account not created yet. Retry $retries of $($script:AADCloudSyncTools.MaxRetries)..."
        }
    }
    While ($keepWaiting)

    Write-Host "Azure AD Cloud Sync Service Account repaired successfully. Please Restart Provisioning from Azure Portal." -ForegroundColor Green
}

<#
.Synopsis
   Resume Azure AD Cloud Sync Job
.DESCRIPTION
   Continues synchronization from the previous watermark.
.EXAMPLE
   Resume-AADCloudSyncToolsJob -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Resume-AADCloudSyncToolsJob
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $Id
    )

    [string] $servicePrincipalId = Get-AADCloudSyncToolsServicePrincipalFromSyncJob -Id $Id
    [string] $method = "POST"
    [string] $uri = "https://graph.microsoft.com/beta/servicePrincipals/$servicePrincipalId/synchronization/jobs/$Id/start"
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
}

<#
.Synopsis
   Pause Azure AD Cloud Sync Job
.DESCRIPTION
   Pauses synchronization.
.EXAMPLE
   Suspend-AADCloudSyncToolsJob -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Suspend-AADCloudSyncToolsJob
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $Id
    )

    [string] $servicePrincipalId = Get-AADCloudSyncToolsServicePrincipalFromSyncJob -Id $Id
    [string] $method = "POST"
    [string] $uri = "https://graph.microsoft.com/beta/servicePrincipals/$servicePrincipalId/synchronization/jobs/$Id/pause"
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body ""
}

<#
.Synopsis
   Restart Azure AD Cloud Sync Job
.DESCRIPTION
   Restarts a full synchronization.
.EXAMPLE
   Restart-AADCloudSyncToolsJob -Id AD2AADProvisioning.3dacc451522540d6be6f70dbfa4fb0123.26effcb4-3ce8-4076-bfbb-79ebc0be0481
#>
Function Restart-AADCloudSyncToolsJob
{
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $Id
    )
    
    [string] $servicePrincipalId = Get-AADCloudSyncToolsServicePrincipalFromSyncJob -Id $Id
    [string] $method = "POST"
    [string] $uri = "https://graph.microsoft.com/beta/servicePrincipals/$servicePrincipalId/synchronization/jobs/$Id/restart"
    [string] $json = "{""criteria"":{""resetScope"":""Full""}}"
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body $json
}

<#
.Synopsis
   Enable AADCloudSyncTools Verbose logging and start tracing
.DESCRIPTION
   Modifies the 'AADConnectProvisioningAgent.exe.config' to enable verbose tracing and restarts the AADConnectProvisioningAgent service
   You can use -SkipServiceRestart to prevent service restart but any config changes will not take effect.
.EXAMPLE
   Start-AADCloudSyncToolsVerboseLogs
.EXAMPLE
   Start-AADCloudSyncToolsVerboseLogs -SkipServiceRestart
#>
Function Start-AADCloudSyncToolsVerboseLogs
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [switch] $SkipServiceRestart
    )
    
    IsAgentPresent
    Set-AADCloudSyncToolsAgentConfigFile -Config VerboseTracing
    Restart-AADCloudSyncToolsAgent -RestartNow (-not $SkipServiceRestart)
}

<#
.Synopsis
   Disable AADCloudSyncTools Verbose logging and stop tracing
.DESCRIPTION
   Modifies the 'AADConnectProvisioningAgent.exe.config' to disable verbose tracing and restarts the AADConnectProvisioningAgent service. 
   You can use -SkipServiceRestart to prevent service restart but any config changes will not take effect.
.EXAMPLE
   Stop-AADCloudSyncToolsVerboseLogs
.EXAMPLE
   Stop-AADCloudSyncToolsVerboseLogs -SkipServiceRestart
#>
Function Stop-AADCloudSyncToolsVerboseLogs
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [switch] $SkipServiceRestart
    )
    
    IsAgentPresent
    Set-AADCloudSyncToolsAgentConfigFile -Config Default
    Restart-AADCloudSyncToolsAgent -RestartNow (-not $SkipServiceRestart)
}

<#
.Synopsis
   Exports all the diagnostics data into a compressed file
.DESCRIPTION
   Exports and packages all the troubleshooting data in a compressed file, as follows:
   1. Starts a verbose tracing with Start-AADCloudSyncToolsVerboseLogs
   2. Collects a trace log for 3 minutes.
      You can specify a different time with -TracingDurationMins or skip verbose tracing with -SkipVerboseTrace
   3. Stops verbose tracing with Stop-AADCloudSyncToolsVerboseLogs
   4. Collects Event Viewer Logs for the last 24 hours
   5. Compresses all the agent logs, verbose logs and event viewer logs into a compressed zip file under the User's Documents folder. 
      You can specify a different output folder with -OutputPath <folder path>
.EXAMPLE
   Export-AADCloudSyncToolsLogs
.EXAMPLE
   Export-AADCloudSyncToolsLogs -SkipVerboseTrace
.EXAMPLE
   Export-AADCloudSyncToolsLogs -OutputPath "C:\Temp"
#>
Function Export-AADCloudSyncToolsLogs
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $false)]
        [switch]
        $SkipVerboseTrace,

        [Parameter(Position = 1, Mandatory = $false)]
        [int]
        $TracingDurationMins = 3,

        [Parameter(Position = 2, Mandatory = $false)]
        [string]
        $OutputPath = [Environment]::GetFolderPath("MyDocuments")

    )
     
    IsAADCloudSyncToolsConnected

    Write-Verbose "Skipping Verbose log: $SkipVerboseTrace"
    $currentDateTimeStr = Get-AADCloudSyncToolsCurrentDateTimeString

    If (-not $SkipVerboseTrace)
    {
        Start-AADCloudSyncToolsVerboseLogs
        Write-host "Capturing Azure AD Cloud Sync Agent verbose log. Please wait $TracingDurationMins minute(s)..." -ForegroundColor Cyan
        Start-Sleep -Seconds $($TracingDurationMins * 60)
        Stop-AADCloudSyncToolsVerboseLogs
    }

    Export-AADCloudSyncToolsEventViewerLogs -Target $script:AADCloudSyncTools.LogDirTarget -DateTimeString $currentDateTimeStr

    Compress-AADCloudSyncToolsAgentLogFiles -Source $script:AADCloudSyncTools.LogDirTarget -Target $OutputPath -DateTimeString $currentDateTimeStr
}

<#
.Synopsis
   Searches members of Azure AD group in AD and prompts the members not found in AD for removing from Azure AD
.DESCRIPTION
   1. This cmdlet accepts objectId of the Azure AD group. If the current logged in user doesn't have enough permissions to
      fetch the AD objects then provide the ADCredential, otherwise skip this parameter.
   2. First the group is looked up in the Azure AD using objectId.
   3. If the group exists in the Azure AD then we use the onPremises properties of the group to search it in the AD.
   4. If the corresponding group exists in the AD then we enumerate all the members of the Azure AD group and look 
      them up in the AD.
   5. The members not found in the AD are prompted to the user for verification and to confirm if it is OK to delete them.
.EXAMPLE
   Remove-AADCloudSyncToolsGroupMembers -AADGroupObjectId "<ObjectId of Azure AD Group>"
.EXAMPLE
   Remove-AADCloudSyncToolsGroupMembers -AADGroupObjectId "<ObjectId of Azure AD Group>" -ADCredential <PSCredential of AD if logged in user doesn't have read permissions> 
#>
Function Remove-AADCloudSyncToolsGroupMembers
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string] $AADGroupObjectId,
        [Parameter(Mandatory=$false)]
        [PSCredential] $ADCredential = $null)

    $scriptDir = Split-Path $script:MyInvocation.MyCommand.Path
    Import-Module ($scriptDir + "\..\Microsoft.CloudSync.Powershell.dll") -Force

    IsAADCloudSyncToolsConnected

    Try
    {
        Write-Verbose "Calling Get-MsalToken: Get-MsalToken -ClientId $($script:AADCloudSyncTools.PAClientId) -TenantId $($script:AADCloudSyncTools.TenantId) -Silent -LoginHint $($script:AADCloudSyncTools.Username) -Scopes $($script:AADCloudSyncTools.Scopes)"
        $script:AADCloudSyncTools.AwsToken = Get-MsalToken -ClientId $script:AADCloudSyncTools.PAClientId -TenantId $script:AADCloudSyncTools.TenantId -Silent -LoginHint $script:AADCloudSyncTools.Username -Scopes $script:AADCloudSyncTools.Scopes
    }
    Catch
    {
        Try
        {
            Write-Verbose "Calling Get-MsalToken: Get-MsalToken -ClientId $($script:AADCloudSyncTools.PAClientId) -TenantId $($script:AADCloudSyncTools.TenantId) -LoginHint $($script:AADCloudSyncTools.Username) -Interactive -ErrorAction Stop -Scopes $($script:AADCloudSyncTools.Scopes)"
            $script:AADCloudSyncTools.AwsToken = Get-MsalToken -ClientId $script:AADCloudSyncTools.PAClientId -TenantId $script:AADCloudSyncTools.TenantId -LoginHint $script:AADCloudSyncTools.Username -Interactive -ErrorAction Stop -Scopes $script:AADCloudSyncTools.Scopes
        }
        Catch
        {
            Throw "There was a problem requesting an access token. Error Details: $($_.Exception.Message)"
        }
    }

    $aadGroup = Get-AADCloudSyncToolsGroup -ObjectId $AADGroupObjectId
    If ($aadGroup -eq $null)
    {
        Write-Host("Group with the objectid not found in the Azure AD:" + $AADGroupObjectId)
    }

    $adGroup = $null
    If ($ADCredential -eq $null)
    {
        $adGroup = Get-ADGroup `
                    -Identity $aadGroup.onPremisesSecurityIdentifier `
                    -Server $aadGroup.onPremisesDomainName
    }
    Else
    {
        $adGroup = Get-ADGroup `
            -Credential $ADCredential `
            -Identity $aadGroup.onPremisesSecurityIdentifier `
            -Server $aadGroup.onPremisesDomainName
    }

    If ($adGroup -eq $null)
    {
        Write-Host "Matching group not found in the AD"
        Return
    }

    [System.Collections.Hashtable]$header = @{'ConsistencyLevel'='eventual'}
    $aadGroupMembers = Get-AADCloudSyncToolsGroupMembers -ObjectId $AADGroupObjectId -Header $header
    If ($aadGroupMembers -eq $null)
    {
        Write-Host "No member found in the Azure AD group with the objectId: $AADGroupObjectId"
        Return
    }
    
    [string[]]$notFoundNames = @()
    [string[]]$notFoundCloudAnchors = @()
    $groupDN = $adGroup.distinguishedName
    $totalObjects = $aadGroupMembers.'@odata.count'
    Do
    {
        Foreach ($aadGroupMember in $aadGroupMembers.Value)
        {
            $objectClass = ""
            $cloudAnchor = ""
            If ($aadGroupMember.'@odata.type' -ieq '#microsoft.graph.user')
            {
                $objectClass = "user"
                $cloudAnchor = "User_" + $aadGroupMember.id
            }
            Elseif ($aadGroupMember.'@odata.type' -ieq '#microsoft.graph.contact')
            {
                $objectClass = "contact"
                $cloudAnchor = "Contact_" + $aadGroupMember.id
            }
            Elseif ($aadGroupMember.'@odata.type' -ieq '#microsoft.graph.group')
            {
                $objectClass = "group"
                $cloudAnchor = "Group_" + $aadGroupMember.id
            }
            $objectSid = $aadGroupMember.onPremisesSecurityIdentifier
            $objectDomain = $aadGroupMember.onPremisesDomainName

            $adObject = $null
            If ($ADCredential -eq $null)
            {
                $adObject = Get-ADObject `
                                -Filter {(objectClass -eq $objectClass) -and (objectSid -eq $objectSid) -and (memberOf -eq $groupDN)} `
                                -Server $objectDomain
            }
            Else
            {
                $adObject = Get-ADObject `
                                -Credential $ADCredential `
                                -Filter {(objectClass -eq $objectClass) -and (objectSid -eq $objectSid) -and (memberOf -eq $groupDN)} `
                                -Server $objectDomain
            }
          
            If ($adObject -eq $null)
            {
                $notFoundCloudAnchors += $cloudAnchor
                $notFoundNames += $aadGroupMember.displayName;
            }
            $objectsProcessed += 1
            Write-Host "Processed $objectsProcessed of $totalObjects members"
        }
        $aadGroupMembers = Get-AADCloudSyncToolsNextPage $aadGroupMembers.'@odata.nextLink' -Header $header
    }While ($aadGroupMembers -ne $null)

    If ($notFoundCloudAnchors.Count -eq 0)
    {
        Write-Host "No member found to be removed from the Azure AD."
        RETURN
    }

    Foreach ($notFoundName in $notFoundNames)
    {
        Write-Host "`"$notFoundName`" is not a member of `"$adGroup.Name`""
    }

    $YesOrNo = Read-Host "Please confirm to delete above member(s) from the Azure AD group (y/n)"
    While ("y","n" -notcontains $YesOrNo)
    {
        $YesOrNo = Read-Host "Please confirm to delete above member(s) from the Azure AD group (y/n)"
    }

    If ("y" -contains $YesOrNo)
    {
        $groupCloudAnchor = "Group_" + $aadGroup.Id
        Remove-AADCloudSyncGroupMembers `
            -GroupCloudAnchor $groupCloudAnchor `
            -MemberAnchors $notFoundCloudAnchors `
            -AccessToken $script:AADCloudSyncTools.AwsToken.AccessToken
    }
}

<#
.Synopsis
   Disables accidentalDeletionPrevention tenant feature.
.DESCRIPTION
   This cmdlet requires TenantId of the Azure AD tenant.
   It will verify if Accidental Deletion Prevention feature, set on the tenant with Azure AD Connect (ADSync, not Cloud Sync), is enabled and disable it.
.EXAMPLE
   Disable-AADCloudSyncToolsDirSyncAccidentalDeletionPrevention -tenantId "340ab039-c6b1-48a5-9ba7-28fe88f83980"
#>
Function Disable-AADCloudSyncToolsDirSyncAccidentalDeletionPrevention
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $tenantId)
        
    
    Write-Verbose "Disabling tenant Accidental Deletion Prevention (TenantId: $tenantId)..."
    $method = "GET"
    $uri = "https://graph.microsoft.com/beta/directory/onPremisesSynchronization/$tenantId"
    $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method
    $queryResultsJson = $response.QueryResults | ConvertFrom-Json
    $syncDeletionPreventionStatus = $queryResultsJson.configuration.accidentalDeletionPrevention.synchronizationPreventionType

    #Verify if tenant accidental deletion prevention is enabled. Disable it if enabled. 
    If (($syncDeletionPreventionStatus -ne "disabled") -and ($syncDeletionPreventionStatus -ne $null))
    {
        $method = "PATCH"
        $params = @{
	        configuration = @{
		        accidentalDeletionPrevention = @{
			        synchronizationPreventionType = "disabled"
		        }
            }
        }
        $json = $params | ConvertTo-Json
        $response = Invoke-AADCloudSyncToolsGraphQuery -Uri $uri -Method $method -Body $json
        $queryResultsJson = $response.QueryResults | ConvertFrom-Json
        If ($queryResultsJson -eq $null)
        {
            Write-Host "Tenant Synchronization Deletion Prevention feature has been disabled" -ForegroundColor Green
        }
        Else
        {
           Return $queryResultsJson 
        } 
    }
    Else
    {
        Write-Host "Tenant Synchronization Deletion Prevention feature is not enabled" -ForegroundColor Yellow
    }
}

#endregion
#=======================================================================================


#=======================================================================================
#region Main
#=======================================================================================

$ErrorActionPreference = "Stop"
InitInternalModuleVariables
IsAADCloudSyncToolsConnected -DontThrowError
Export-ModuleMember `
    Install-AADCloudSyncToolsPrerequisites  ,`
    Connect-AADCloudSyncTools               ,`
    Set-AADCloudSyncToolsTenantId           ,`
    Get-AADCloudSyncToolsServiceAccount     ,`
    Get-AADCloudSyncToolsInfo               ,`
    Get-AADCloudSyncToolsServicePrincipal   ,`
    Get-AADCloudSyncToolsJob                ,`
    Get-AADCloudSyncToolsJobSchedule        ,`
    Get-AADCloudSyncToolsJobSchema          ,`
    Set-AADCloudSyncToolsJobSchema          ,`
    Get-AADCloudSyncToolsJobSettings        ,`
    Get-AADCloudSyncToolsJobStatus          ,`
    Get-AADCloudSyncToolsJobScope           ,`
    Invoke-AADCloudSyncToolsGraphQuery      ,`
    Repair-AADCloudSyncToolsAccount         ,`
    Resume-AADCloudSyncToolsJob             ,`
    Suspend-AADCloudSyncToolsJob            ,`
    Restart-AADCloudSyncToolsJob            ,`
    Start-AADCloudSyncToolsVerboseLogs      ,`
    Stop-AADCloudSyncToolsVerboseLogs       ,`
    Export-AADCloudSyncToolsLogs            ,`
    Remove-AADCloudSyncToolsGroupMembers    ,`
    Disable-AADCloudSyncToolsDirSyncAccidentalDeletionPrevention
#endregion
#=======================================================================================

# SIG # Begin signature block
# MIInvgYJKoZIhvcNAQcCoIInrzCCJ6sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC+hUC3pdOYjd2U
# skQiMxxftJdgr5YKOBHtdFAuoa1zG6CCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ4wghmaAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMATOK2Mj3HWzEOQqnnpdp/N
# I02d1XON3q7CtwIOj51/MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAi8T9qg2g1hiFaigp36K+1v7L40hCIUO44uzm///RQ88b81hQjQm9iF4W
# itP1lAbdok1mxa32SToU4E0bnNCKldYiOnPjCp9PuGt70IJnSA4jTR11HqZGXPDh
# 1AJWsSlp6h+l70zyXRU1srqmYYUj6Rc//araJfYjcledfb+LdcfTFGarjFJCl8/x
# ERRh/qBa9N8Clc6VBlM69T9UVY9mzLATKtTZo6JL4KAXkxpZekMVEQZfM831t4S9
# oFoRHoL/qPXqIPatcGgvC0O10hJfRmIrIP5VBonGdBmAhltpqaztesgaY10MfQRP
# zIBTsm63WFNtS5eYNPj5pYWYgrcZ8aGCFygwghckBgorBgEEAYI3AwMBMYIXFDCC
# FxAGCSqGSIb3DQEHAqCCFwEwghb9AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFYBgsq
# hkiG9w0BCRABBKCCAUcEggFDMIIBPwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDc8Emwnj2T5hak08BXNDFr8n0vqGbrWjp+t4PM3O0AbgIGZfHOIDHt
# GBIyMDI0MDMxNDIzMDMzOS44MVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVs
# YW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# MDg0Mi00QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAdqO1claANERsQABAAAB2jANBgkq
# hkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEw
# MTIxOTA2NTlaFw0yNTAxMTAxOTA2NTlaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
# YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDItNEJF
# Ni1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk5AGCHa1UVHWPyNADg0N/xtx
# WtdI3TzQI0o9JCjtLnuwKc9TQUoXjvDYvqoe3CbgScKUXZyu5cWn+Xs+kxCDbkTt
# fzEOa/GvwEETqIBIA8J+tN5u68CxlZwliHLumuAK4F/s6J1emCxbXLynpWzuwPZq
# 6n/S695jF5eUq2w+MwKmUeSTRtr4eAuGjQnrwp2OLcMzYrn3AfL3Gu2xgr5f16ts
# MZnaaZffvrlpLlDv+6APExWDPKPzTImfpQueScP2LiRRDFWGpXV1z8MXpQF67N+6
# SQx53u2vNQRkxHKVruqG/BR5CWDMJCGlmPP7OxCCleU9zO8Z3SKqvuUALB9UaiDm
# mUjN0TG+3VMDwmZ5/zX1pMrAfUhUQjBgsDq69LyRF0DpHG8xxv/+6U2Mi4Zx7LKQ
# wBcTKdWssb1W8rit+sKwYvePfQuaJ26D6jCtwKNBqBiasaTWEHKReKWj1gHxDLLl
# DUqEa4frlXfMXLxrSTBsoFGzxVHge2g9jD3PUN1wl9kE7Z2HNffIAyKkIabpKa+a
# 9q9GxeHLzTmOICkPI36zT9vuizbPyJFYYmToz265Pbj3eAVX/0ksaDlgkkIlcj7L
# GQ785edkmy4a3T7NYt0dLhchcEbXug+7kqwV9FMdESWhHZ0jobBprEjIPJIdg628
# jJ2Vru7iV+d8KNj+opMCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBShfI3JUT1mE5WL
# MRRXCE2Avw9fRTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAuYNV1O24jSMAS3jU
# 7Y4zwJTbftMYzKGsavsXMoIQVpfG2iqT8g5tCuKrVxodWHa/K5DbifPdN04G/uty
# z+qc+M7GdcUvJk95pYuw24BFWZRWLJVheNdgHkPDNpZmBJxjwYovvIaPJauHvxYl
# SCHusTX7lUPmHT/quz10FGoDMj1+FnPuymyO3y+fHnRYTFsFJIfut9psd6d2l6pt
# OZb9F9xpP4YUixP6DZ6PvBEoir9CGeygXyakU08dXWr9Yr+sX8KGi+SEkwO+Wq0R
# NaL3saiU5IpqZkL1tiBw8p/Pbx53blYnLXRW1D0/n4L/Z058NrPVGZ45vbspt6CF
# rRJ89yuJN85FW+o8NJref03t2FNjv7j0jx6+hp32F1nwJ8g49+3C3fFNfZGExkkJ
# WgWVpsdy99vzitoUzpzPkRiT7HVpUSJe2ArpHTGfXCMxcd/QBaVKOpGTO9KdErMW
# xnASXvhVqGUpWEj4KL1FP37oZzTFbMnvNAhQUTcmKLHn7sovwCsd8Fj1QUvPiydu
# gntCKncgANuRThkvSJDyPwjGtrtpJh9OhR5+Zy3d0zr19/gR6HYqH02wqKKmHnz0
# Cn/FLWMRKWt+Mv+D9luhpLl31rZ8Dn3ya5sO8sPnHk8/fvvTS+b9j48iGanZ9O+5
# Layd15kGbJOpxQ0dE2YKT6eNXecwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZ
# AAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVa
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1
# V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9
# alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmv
# Haus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928
# jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3t
# pK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEe
# HT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26o
# ElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4C
# vEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ug
# poMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXps
# xREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0C
# AwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYE
# FCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtT
# NRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBD
# AEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZW
# y4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5t
# aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAt
# MDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0y
# My5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pc
# FLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpT
# Td2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0j
# VOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3
# +SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmR
# sqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSw
# ethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5b
# RAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmx
# aQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsX
# HRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0
# W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0
# HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFu
# ZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4
# NDItNEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloiMKAQEwBwYFKw4DAhoDFQBCoh8hiWMdRs2hjT/COFdGf+xIDaCBgzCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA
# 6Z2drzAiGA8yMDI0MDMxNTAwMDA0N1oYDzIwMjQwMzE2MDAwMDQ3WjB0MDoGCisG
# AQQBhFkKBAExLDAqMAoCBQDpnZ2vAgEAMAcCAQACAiTzMAcCAQACAikmMAoCBQDp
# nu8vAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMH
# oSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEApuaK822OY999355TKjVh
# Pz2UxoQGaxW4vYmcY2Jhaow3go0ZTVkazxO96La7w4JQ8GioDUDrNeFvm4+rcCuF
# AYh9UKCIbdzW9BFyIhcR3EbPrCoPVBK/WP/FBbvQtdYJlhPAWg8kadX7S2ClKEXo
# j/6pcvBSPM7GsCm8KwNl4WIxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAdqO1claANERsQABAAAB2jANBglghkgBZQMEAgEF
# AKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEi
# BCBEcvLLXmFoFmY7U66Uf86FuAteLeI1Kx4BLkmSKTeC6DCB+gYLKoZIhvcNAQkQ
# Ai8xgeowgecwgeQwgb0EICKlo2liwO+epN73kOPULT3TbQjmWOJutb+d0gI7GD3G
# MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHajtXJ
# WgDREbEAAQAAAdowIgQg7tnypA0HNoInxIcS91tLKROnjcjM1qXf69OwCzsqulUw
# DQYJKoZIhvcNAQELBQAEggIABb339lijvI6cEOCfrZ+lEtbr0qBKXaOuKClnEmQ3
# jTKQVnAmRpiLolMzOP6XpUWJqWl7sSWHhRcgB1WUeXvMfVOkkVP6Hbuli2Bb2D0I
# cCjjCLBaDTZvUd381PDzHRH3fJ592vvjCBXFADqdpTwsLVvfXeNbJzD2xUUw63rl
# 6drFzjJEM9uolupT+b+Q4BwPy5WW2VY2ZuKt2w7RLQeSOlJO3NV0NaI9Ob5qp6EM
# mbGlJE18VVTwYgMwXf4b2V5SFoGT0tYXDhUiGkDoySxGvs+thIeKqMUO2sDrvNNP
# xuv1DVzAolXFKC7Ca/R4aX9I6WMWwAaxdmP3VTy+GDTp+w6XHqMFvW9tC8j/K4MY
# E2YC/t3CJrVuczIsUXLOZBc0QKwWw5g32aNDaN8us6/LjUuga5ZR6kRJu332OkKZ
# viwdtgvrXbIixEULtb8oS/NBE0o9Atg/F3gBHrk2jDrsEo/UE2E4wDE/3KthtCFA
# 1bwvNqc3Ivgi9CjS4gABnjHujKrK6QtAMDsk83/RIHF6KEPM5vrgIRwTpE1bJUeU
# rkgUaL50TmHj5zSVAMiihzu1hAJDNadXc3O3tTMHXE5rMTGDG+bO/xVUB7D7meCn
# vRKFE72XUF1NThGMQq6Hikj5gqY96cwdvV0SeD3YQF0yfNX1wq0nRN7zVLa1/gid
# sUQ=
# SIG # End signature block
