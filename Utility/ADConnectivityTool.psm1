<#

.SYNOPSIS
    Detects connectivity issues between AADConnect and Active Directory.

.DESCRIPTION
    ADConnectivityTools.psm1 is a Windows PowerShell script module that provides functions that are
    used to detect issues when link forests to AADConnect during the "Connect your directories" step
    of AADConnect's installation wizard.
#>

#----------------------------------------------------------
# STATIC VARIABLES
#----------------------------------------------------------
$MinAdForestVersion = [System.DirectoryServices.ActiveDirectory.ForestMode]::Windows2003Forest

# 53 - DNS
# 88 - Kerberos
# 389 - LDAP
$Ports = @('53', '88', '389')
$PortsNoDns = @('88', '389')

# PSCredential object that will be shared across the whole module
#[System.Management.Automation.PSCredential] $Script:Credentials


#region Network Connectivity Validation

<#
    .SYNOPSIS
        Detects local network connectivity issues.

    .DESCRIPTION
        Runs local network connectivity tests.

        For the local networking tests, AAD Connect must be able to communicate with the named
        domain controllers on ports 53 (DNS), 88 (Kerberos) and 389 (LDAP) Most organizations run DNS
        on their DCs, which is why this test is currently integrated. Port 53 should be skipped
        if another DNS server has been specified.

    .PARAMETER SkipDnsPort
        If user is not using DNS services provided by the AD Site / Logon DC, then he\she may want
        to skip checking port 53.  User must still be able to resolve _.ldap._tcp.<forestfqdn>
        in order for the Active Directory Connector configuration to succeed.

    .PARAMETER DCs
        Specify DCs to test against.

    .PARAMETER ReturnResultAsPSObject
        Returns the result of this diagnosis in the form of a PSObject. Not necessary during manual interaction with
        this tool.

    .EXAMPLE
        Confirm-NetworkConnectivity -SkipDnsPort -DCs "MYDC1.CONTOSO.COM","MYDC2.CONTOSO.COM"

    .EXAMPLE
        Confirm-NetworkConnectivity -DCs "MYDC1.CONTOSO.COM","MYDC2.CONTOSO.COM" -Verbose
#>
Function Confirm-NetworkConnectivity
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [array] $DCs,

        [switch] $SkipDnsPort,

        [switch] $ReturnResultAsPSObject
    )

    If($SkipDnsPort)
    {
        $Ports = $PortsNoDns
    }

    # Test connectivity on every DC on every Port.
    Foreach ($DC in $DCs)
    {
        Foreach ($Port in $Ports)
        {
            Try
            {
                # Test connection.
                $Result = (Test-NetConnection -ComputerName $DC -Port $Port -ErrorAction Stop -WarningAction SilentlyContinue)
                Switch ($Result.TcpTestSucceeded)
                {
                    True
                    {
                        Write-Log "TCP connection to $($DC) on port $($Port) succeeded." -ForegroundColor Green
                    }
                    False
                    {
                        Write-Log
                        Write-Log "TCP connection to $($DC) on port $($Port) failed. " -ForegroundColor Red
                        Write-Log
                        Write-Log "WHAT TO TRY NEXT:" -ForegroundColor Yellow
                        Write-Log
                        Write-Log "`t Please make sure this port is not blocked. This check can be performed in `"Windows Firewall with" -ForegroundColor Yellow
                        Write-Log "`t Advanced Security`" by determining if there are not any firewall rules enabled and pointing to this" -ForegroundColor Yellow
                        Write-Log "`t port." -ForegroundColor Yellow
                        Write-Log
                        Write-Log "---------------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
                        Write-Log
                        Write-Log "`t The command that failed was: Confirm-NetworkConnectivity. You may try it again once you think the " -ForegroundColor Yellow
                        Write-Log "`t problem is solved. Or you can try with Start-NetworkConnectivityDiagnosisTools if you prefer running all" -ForegroundColor Yellow
                        Write-Log "`t network connectivity tests from the start." -ForegroundColor Yellow
                        Write-Log
                        If($ReturnResultAsPSObject) {
                            Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::TCPConnectionFailed) -AssociatedMessage ($DC + ':' + $Port)
                        }
                        Return $False
                    }
                }
                Write-Log "Debug entry for $($DC) [$($Result.RemoteAddress)]:$($Port)."
                Write-Log "Remote endpoint: $($DC)"
                Write-Log "Remote port: $($Result.RemotePort)"
                Write-Log "Interface Alias: $($Result.InterfaceAlias)"
                Write-Log "Source Interface Address: $($Result.SourceAddress.IPAddress)"
                Write-Log "Ping Succeeded: $($Result.PingSucceeded)"
                Write-Log "Ping Reply Time (RTT) Status: $($Result.PingReplyDetails.Status)"
                Write-Log "Ping Reply Time (RTT) RoundTripTime: $($Result.PingReplyDetails.RoundtripTime)"
                Write-Log "TCPTestSucceeded: $($Result.TcpTestSucceeded)"
            }
            Catch
            {
                If($ReturnResultAsPSObject)
                {
                    Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::CallToTestNetConnectionFailed) -AssociatedMessage ($_.Exception.Message)
                }
                Write-Error "Error while testing TCP connectivity on $DC port: $Port. Exception message: $($_.Exception.Message). Please try again"
                Return $False
            }
        }
    }
    If($ReturnResultAsPSObject)
    {
        Return $null
    }
    Return $True
}

<#
    .SYNOPSIS
        Detects local Dns issues.

    .DESCRIPTION
        Runs local Dns connectivity tests.
        In order to configure the Active Directory connector, user must have both name resolution
        for the forest he\she is attempting to connect to as well as in the domain controllers
        associated to this forest.

    .PARAMETER Forest
        Specifies the name of the forest to test against.

    .PARAMETER DCs
        Specify DCs to test against.

    .PARAMETER ReturnResultAsPSObject
        Returns the result of this diagnosis in the form of a PSObject. Not necessary during manual interaction with
        this tool.

    .EXAMPLE
        Confirm-DnsConnectivity -Forest "TEST.CONTOSO.COM" -DCs "MYDC1.CONTOSO.COM","MYDC2.CONTOSO.COM"

    .EXAMPLE
        Confirm-DnsConnectivity -Forest "TEST.CONTOSO.COM"
#>
Function Confirm-DnsConnectivity
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $Forest,

        [Parameter(Mandatory=$True)]
        [array] $DCs,

        [switch] $ReturnResultAsPSObject
    )

    # Get DNS targets.
    $DnsTargets = @("_ldap._tcp.$Forest") + $DCs

    Foreach ($HostName in $DnsTargets)
    {
        Try
        {
            # Resolve DNS.
            $DnsResult = Resolve-DnsName -Type ANY $HostName -ErrorAction Stop -WarningAction SilentlyContinue
            If ($DnsResult.Name)
            {
                Write-Log "Successfully resolved $($HostName)." -ForegroundColor Green
            }
            Else
            {
                Write-Log "Error attempting DNS resolution for $($HostName). DnsResult: $DnsResult" -ForegroundColor Red
                Write-Log
                Write-Log "WHAT TO TRY NEXT:" -ForegroundColor Yellow
                Write-Log
                Write-Log "`t Please refer to http://go.microsoft.com/fwlink/?LinkID=48893 or contact your network administrator" -ForegroundColor Yellow
                Write-Log "`t to resolve this issue." -ForegroundColor Yellow
                Write-Log
                Write-Log "---------------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
                Write-Log
                Write-Log "`t The command that failed was: Confirm-DnsConnectivity. You may try it again once you think the " -ForegroundColor Yellow
                Write-Log "`t problem is solved. Or you can try with Start-NetworkConnectivityDiagnosisTools if you prefer running all" -ForegroundColor Yellow
                Write-Log "`t network connectivity tests from the start." -ForegroundColor Yellow
                Write-Log
                if($ReturnResultAsPSObject)
                {
                    Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::DNSResolutionFailed) -AssociatedMessage $HostName
                }
                Return $False
            }
        }
        Catch
        {
            if($ReturnResultAsPSObject)
            {
                Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::CallToResolveDNSNameFailed) -AssociatedMessage ($_.Exception.Message)
            }
            Write-Error "Error while calling Resolve-DnsName. Exception message: $($_.Exception.Message). Please try again"
            Return $False
        }
    }
    if($ReturnResultAsPSObject)
    {
        Return $null
    }
    Return $True
}

<#
    .SYNOPSIS
        Determines if a specified forest and its associated Domain Controllers are reachable.

    .DESCRIPTION
        Runs "ping" tests (whether a computer can reach a destination computer through the network
        and/or the internet)

    .PARAMETER Forest
        Specifies the name of the forest to test against.

    .PARAMETER DCs
        Specify DCs to test against.

    .EXAMPLE
        Confirm-TargetsAreReachable -Forest "TEST.CONTOSO.COM" -DCs "MYDC1.CONTOSO.COM","MYDC2.CONTOSO.COM"

    .EXAMPLE
        Confirm-TargetsAreReachable -Forest "TEST.CONTOSO.COM"
#>
Function Confirm-TargetsAreReachable
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $Forest,

        [Parameter(Mandatory=$True)]
        [array] $DCs
    )

    $Destinations = @("$Forest") +  $DCs

    Foreach($Destination in $Destinations)
    {
        $Result = ping $Destination
        If($Result.SyncRoot)
        {
            Write-Log "$Destination is reachable." -ForegroundColor Green
        }
        Else
        {
            Write-Log "Ping failed! $Destination is not reachable." -ForegroundColor Red
            Write-Log "This failure can be ignored in case your Firewall is not allowing ICMP." -ForegroundColor Yellow
            Write-Log
        }
    }
}

<#
    .SYNOPSIS
        Determines if a specified forest exists.

    .DESCRIPTION
        Queries a DNS server for the IP addresses associated with a forest.

    .PARAMETER Forest
        Specifies the name of the forest to test against.

    .EXAMPLE
        Confirm-TargetsAreReachable -Forest "TEST.CONTOSO.COM"
#>
Function Confirm-ForestExists
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $Forest
    )
    Try
    {
        [System.Net.Dns]::GetHostAddresses($Forest)
        Write-Log "$Forest exists" -ForegroundColor Green
        Return $True
    }
    Catch
    {
        Write-Log "$Forest could not be reached." -ForegroundColor Red
        Write-Log
        Write-Log "WHAT TO TRY NEXT:" -ForegroundColor Yellow
        Write-Log
        Write-Log "`t Please verify you have typed the forest name correctly and that the Active Directory Domain Services" -ForegroundColor Yellow
        Write-Log "`t service is running on all the Domain Controller(s) associated with $Forest " -ForegroundColor Yellow
        Write-Log
        Write-Log "`t The command that failed was: Confirm-ForestExists. You may try it again once you think the " -ForegroundColor Yellow
        Write-Log "`t problem is solved. Or you can try with Start-NetworkConnectivityDiagnosisTools if you prefer running all" -ForegroundColor Yellow
        Write-Log "`t network connectivity tests from the start." -ForegroundColor Yellow
        Return $False
    }
}

# Helper function to retrieve the name of the forest associated to the server in which AADConnect is being installed.
Function Get-CurrentForestName
{
    Param(
        [switch] $ValidCredentials
    )
    Try
    {
        $ForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
        Return $ForestName
    }
    Catch
    {
        Write-Log "Cannot retrieve the forest that this machine is logged to." -ForegroundColor Red
        Write-Log
        Write-Log "WHAT TO TRY NEXT:" -ForegroundColor Yellow
        Write-Log
        if($ValidCredentials)
        {
            Write-Log "`t Even though the provided credentials were valid, we found the following issue: " -ForegroundColor Yellow
        }
        Write-Log "`t Unable to establish a connection to the current local computer's forest. Please make sure the Active " -ForegroundColor Yellow
        Write-Log "`t Directory Domain Services service is running and UDP and TCP ports 389 are open in the Domain Controller(s) " -ForegroundColor Yellow
        Write-Log "`t associated with the current local computer's forest. (The user has to perform this manual check on the" -ForegroundColor Yellow
        Write-Log "`t `"Windows Firewall with Advanced Security`" window. There must not be any firewall rules blocking these ports)." -ForegroundColor Yellow
        Write-Log
        Return $null
    }
}

# Helper function for network connectivity tests.
Function Get-DCsInForest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $ForestName

        # We need the user credentials to address the scenario in which AADConnect is
        # installed on a different forest than the target forest.
        #[Parameter(Mandatory=$True)]
        #[System.Management.Automation.PSCredential] $Credentials
    )

    # A side-functionality of Get-ForestFQDN is to validate UDP connection on port 389.
    $Forest = Get-ForestFQDN -Forest $ForestName

    If($Forest -eq $null)
    {
        Write-Log "Cannot retrieve DCs associated to a forest named: $ForestName." -ForegroundColor Red
        Write-Log
        Write-Log "WHAT TO TRY NEXT:" -ForegroundColor Yellow
        Write-Log
        Write-Log "`t Cannot establish a connection to the Domain Controller(s) associated to a forest named: `"$ForestName`"." -ForegroundColor Yellow
        Write-Log "`t Please make sure of the following:"
        Write-Log "`t - The Credentials (Username and Password) you have provided are correct" -ForegroundColor Yellow
        Write-Log "`t - UDP and TCP port 389 are open in these DCs (you have to perform this manual check on the `"Windows " -ForegroundColor Yellow
        Write-Log "`t Firewall with Advanced Security`" window on every Domain Controller)" -ForegroundColor Yellow
        Write-Log
        Return $null
    }

    Foreach($Domain in $Forest.Domains)
    {
        (Get-ADDomainController -Filter * -Server $Domain).HostName
    }
}

# Auxiliary enum that describes the different network connectivity errors detected by this tool.
Add-Type -TypeDefinition @"
    public enum ADConnectivityToolErrorCodes
    {
        NoError,
        ForestNotFound,
        CannotContactDCs,
        DNSResolutionFailed,
        CallToResolveDNSNameFailed,
        TCPConnectionFailed,
        CallToTestNetConnectionFailed,
        UnableToRetrieveForestName_ValidCredentials,
        UnableToRetrieveForestName_InvalidCredentials,
        InvalidCredentials_UsernameOrPassword,
        InvalidCredentials_Domain
    }
"@

#Auxiliary Function that creates a PSObject AADConnect Wizard is going to read.
Function Get-NetworkDiagnosisResultObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ADConnectivityToolErrorCodes] $ADConnectivityToolErrorCode,

        [Parameter(Mandatory=$True)]
        [string] $AssociatedMessage
    )

    $NetworkDiagnosisResult = New-Object -TypeName psobject

    # We pass the numeric value of the error code, so the AADConnect Wizard can interpret the cause of the problem.
    $NetworkDiagnosisResult | Add-Member -MemberType NoteProperty -Name ADConnectivityToolErrorCode -Value $ADConnectivityToolErrorCode.value__

    # AssociatedMessage is a generic string that will hold the name of a Forest or a DC that are failing or an exception message, etc.
    $NetworkDiagnosisResult | Add-Member -MemberType NoteProperty -Name AssociatedMessage -Value $AssociatedMessage

    Return $NetworkDiagnosisResult
}

<#
    .SYNOPSIS
        Main function for network connectivity tests.

    .DESCRIPTION
        Runs local network connectivity tests.

    .PARAMETER Forest
        Specifies forest name to test against.

    .PARAMETER DCs
        Specify DCs to test against.

    .PARAMETER LogFileLocation
        Specifies a the location of a log file that will contain the output of this function.

    .PARAMETER DisplayInformativeMessage
        Flag that allows displaying a message about the purpose of this function.

    .PARAMETER ReturnResultAsPSObject
        Returns the result of this diagnosis in the form of a PSObject. Not necessary to specify during manual interaction with
        this tool.

    .PARAMETER ValidCredentials
        Indicates if the credentials the user typed are valid. Not necessary to specify during manual interaction with
        this tool.

     .EXAMPLE
        Start-NetworkConnectivityDiagnosisTools -Forest "TEST.CONTOSO.COM"

         .EXAMPLE
        Start-NetworkConnectivityDiagnosisTools -Forest "TEST.CONTOSO.COM" -DCs "DC1.TEST.CONTOSO.COM", "DC2.TEST.CONTOSO.COM"
#>
Function Start-NetworkConnectivityDiagnosisTools
{
    Param(
        [Parameter(Mandatory=$False)]
        [string] $Forest,

        #[Parameter(Mandatory=$True)]
        #[System.Management.Automation.PSCredential] $Credentials,

        [Parameter(Mandatory=$False)]
        [string] $LogFileLocation,

        [Parameter(Mandatory=$False)]
        [array] $DCs,

        [switch] $DisplayInformativeMessage,

        [switch] $ReturnResultAsPSObject,

        [switch] $ValidCredentials
    )

    # Make sure the Global Credentials object is populated before performing network connectivity diagnosis.
    #$Script:Credentials = $Credentials

    Add-WindowsFeature RSAT-AD-PowerShell
    Import-Module ActiveDirectory

    if($DisplayInformativeMessage)
    {
        Write-Log
        Write-Log "There has been a problem while validating connectivity between AADConnect and the Active Directory." -ForegroundColor Yellow
        Write-Log "An attempt to diagnose the problem will be performed by running a set of network connectivity tests" -ForegroundColor Yellow
        Write-Log
        Read-host  "Press ENTER to continue"
    }

    Write-Log
    Write-Log "Starting NetworkConnectivityDiagnosisTools" -ForegroundColor Magenta
    Write-Log

    # Custom-install scenario
    If($Forest)
    {
        Write-Log
        Write-Log "Verifying that `'$Forest`' exists" -ForegroundColor Yellow
        Write-Log

        $ForestExists = Confirm-ForestExists -Forest $Forest
        If(-not $ForestExists)
        {
            If($ReturnResultAsPSObject)
            {
                Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::ForestNotFound) -AssociatedMessage $Forest
            }
            Return
        }
    }
    # Express-install scenario
    Else
    {
        Write-Log
        Write-Log "No Forest name was provided. Attempting to retrieve the forest that this machine is logged to." -ForegroundColor Yellow
        Write-Log

        If($ValidCredentials)
        {
            $Forest = Get-CurrentForestName -ValidCredentials
        }
        Else
        {
            $Forest = Get-CurrentForestName
        }
        If(-not $Forest) {
            If($ReturnResultAsPSObject)
            {
                If($ValidCredentials)
                {
                    Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::UnableToRetrieveForestName_ValidCredentials) -AssociatedMessage "NA"
                }
                Else
                {
                    Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::UnableToRetrieveForestName_InvalidCredentials) -AssociatedMessage "NA"
                }
            }
            Return
        }
    }

    Write-Log
    Write-Log "Verifying if the provided credentials are correct" -ForegroundColor Yellow
    Write-Log

    $Exception = Get-DomainFQDNData -Verbose -ReturnExceptionOnError
    If($Exception -ne $null)
    {
        Write-Log "There was an error during the validation of the credentials you have entered. Details: $($Exception.Message)" -ForegroundColor Red
        If($ReturnResultAsPSObject)
        {
            If($Exception.ErrorRecord.FullyQualifiedErrorId.Equals("AuthenticationException"))
            {
                Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::InvalidCredentials_UsernameOrPassword) -AssociatedMessage "NA"
            }
            Else
            {
                Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::InvalidCredentials_Domain) -AssociatedMessage "NA"
            }
        }
        Return
    }
    Write-Log
    Write-Log "The provided credentials were correct" -ForegroundColor Green
    Write-Log

    Write-Log
    Write-Log "Attempting to obtain Domain Controllers associated with $Forest" -ForegroundColor Yellow
    Write-Log

    If(-not $DCs)
    {
        $DCs = Get-DCsInForest -ForestName $Forest
        If($DCs -eq $null)
        {
            If($ReturnResultAsPSObject)
            {
                Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::CannotContactDCs) -AssociatedMessage $Forest
            }
            Return
        }
        Else
        {
            Write-Log "The following DCs where found:" -ForegroundColor Green
            ForEach($DC in $DCs)
            {
                Write-Log "- $DC" -ForegroundColor Green
            }
            Write-Log
        }
    }

    Write-Log "Validating DNS connectivity." -ForegroundColor Yellow
    Write-Log
    If($ReturnResultAsPSObject)
    {
        $ResultAsPSObject = Confirm-DnsConnectivity -Forest $Forest -DCs $DCs -ReturnResultAsPSObject
        If($ResultAsPSObject -ne $null)
        {
            Return $ResultAsPSObject
        }
    }
    Else
    {
        $Result = Confirm-DnsConnectivity -Forest $Forest -DCs $DCs
        If(-not $Result)
        {
            Return
        }
    }
    Write-Log
    Write-Log

    Write-Log "Determining if provided Forest and its associated DCs are reachable." -ForegroundColor Yellow
    Write-Log
    Confirm-TargetsAreReachable -Forest $Forest -DCs $DCs
    Write-Log
    Write-Log

    Write-Log "Validating network connectivity." -ForegroundColor Yellow
    Write-Log
    If($ReturnResultAsPSObject)
    {
        $ResultAsPSObject = Confirm-NetworkConnectivity -DCs $DCs -ReturnResultAsPSObject
        If($ResultAsPSObject -ne $null)
        {
            Return $ResultAsPSObject
        }
    }
    Else
    {
        $Result = Confirm-NetworkConnectivity -DCs $DCs -Verbose
        If(-not $Result)
        {
            Return
        }
    }
    Write-Log
    Write-Log

    If($ReturnResultAsPSObject) {
        Return Get-NetworkDiagnosisResultObject -ADConnectivityToolErrorCode ([ADConnectivityToolErrorCodes]::NoError) -AssociatedMessage "NA"
    }
    Write-Log "ALL NETWORK CONNECTIVITY TESTS HAVE PASSED." -ForegroundColor Magenta
}

#endregion

#region AD Connectivity Validation

<#
    .SYNOPSIS
        Retrieves a DomainFQDN out of an account and password combination.

    .DESCRIPTION
        Attempts to obtain a domainFQDN object out of provided credentials. If the domainFQDN is valid,
        a DomainFQDNName or RootDomainName will be returned, depending on the user's choice. Account (Domain\Username)
        and Password may be requested.

    .PARAMETER DomainFQDNDataType
        Desired kind of data that will be retrieved. Currently limited to "DomainFQDNName" or "RootDomainName".

    .PARAMETER RunWithCurrentlyLoggedInUserCredentials
        The function will use the credentials of the user that is currently logged in the computer, rather than
        requesting custom credentials from the user.

    .PARAMETER ReturnExceptionOnError
        Auxiliary parameter used by Start-NetworkConnectivityDiagnosisTools function

    .EXAMPLE
       Get-DomainFQDNData -DomainFQDNDataType DomainFQDNName -Verbose

    .EXAMPLE
       Get-DomainFQDNData -DomainFQDNDataType RootDomainName -RunWithCurrentlyLoggedInUserCredentials
#>
Function Get-DomainFQDNData
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("DomainFQDNName","RootDomainName")]
        [string] $DomainFQDNDataType,

        [switch] $RunWithCurrentlyLoggedInUserCredentials,

        [switch] $ReturnExceptionOnError
    )

    Write-Log "Attempting to obtain a domainFQDN" -ForegroundColor Yellow

    $DomainName = (Get-ADDomain).DNSRoot

    Write-Log "Using credentials of the user that is currently logged in. Domain Name will be: $DomainName"

    $DirectoryContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $DomainName)


    Write-Log "Attempting to retrieve DomainFQDN object..."
    Try
    {
        $DomainFQDN = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DirectoryContext)
    }
    Catch
    {
        If($ReturnExceptionOnError) {
            Return $_.Exception
        }
        Else
        {
            Write-Log $_.Exception.Message -ForegroundColor Red
            Write-Log
        }
        Return
    }

    # Return DomainFQDNName or RootDomainName.
    If ($DomainFQDNDataType -eq "DomainFQDNName")
    {
        Write-Log "DomainFQDN obtained" -ForegroundColor Green
        Return $DomainFQDN.Name
    }
    ElseIf($DomainFQDNDataType -eq "RootDomainName")
    {
        Write-Log "RootDomainName obtained" -ForegroundColor Green
        Return $DomainFQDN.Forest.Name
    }
    Return
}


<#
    .SYNOPSIS
        Verifies if a user has Enterprise Admin credentials.

    .DESCRIPTION
        Searches if provided user has Enterprise Admin credentials. Account (Domain\Username) and Password may
        be requested.

    .PARAMETER RunWithCurrentlyLoggedInUserCredentials
        The function will use the credentials of the user that is currently logged in the computer, rather than
        requesting custom credentials from the user.

    .EXAMPLE
        Confirm-ValidEnterpriseAdminCredentials -DomainName test.contoso.com -Verbose

    .EXAMPLE
        Confirm-ValidEnterpriseAdminCredentials -RunWithCurrentlyLoggedInUserCredentials -Verbose
#>
Function Confirm-ValidEnterpriseAdminCredentials
{
    [CmdletBinding()]
    Param(
        [switch] $RunWithCurrentlyLoggedInUserCredentials
    )

    Write-Log "Verifying provided credentials belong to Enterprise Admins group" -ForegroundColor Yellow

    # Define the kind of Sid we will look for.
    $SidType = [System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid

        # Retrieve RootDomainName
        $RootDomainName = Get-DomainFQDNData -DomainFQDNDataType RootDomainName -RunWithCurrentlyLoggedInUserCredentials

        Write-Log "Checking if the currently logged in user has $SidType privileges in $RootDomainName" -ForegroundColor Yellow

        # Get DirectoryEntry from DomainFQDN.
        $DirectoryContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", $RootDomainName)

        $UserName = $env:UserName

    Write-Log "Attempting to retrieve DomainFQDN object..."
    Try
    {
        $DomainFQDN = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DirectoryContext)
        $DirectoryEntry = $DomainFQDN.GetDirectoryEntry()
    }
    Catch
    {
        Write-Log $_.Exception.Message -ForegroundColor Red
        Return $False
    }

    # Obtain the DomainId as an array of bytes.
    [byte[]]$DomainSidInBytes = $DirectoryEntry.Properties["objectSid"].Value

    # Extract DomainSid and GroupSid
    $TargetDomainSid = New-Object System.Security.Principal.SecurityIdentifier($DomainSidInBytes, 0)
    $TargetGroupSid = New-Object System.Security.Principal.SecurityIdentifier($SidType, $TargetDomainSid)

    Write-Log "DomainSid - $TargetDomainSid, GroupSid - $TargetGroupSid"

    # Retrieve the group Sid of the groups the user is subscribed to.
    $GroupSids = GetGroupMembershipSidsForUser

    # Try to match the TargetGroupSid with any of the GroupSid's we just retrieved.
    Foreach ($GroupSid in $GroupSids)
    {
        If ($GroupSid -eq $TargetGroupSid)
        {
            Write-Log "EA membership was found!" -ForegroundColor Green
            Return $True
        }
    }
    Write-Log "EA membership not found." -ForegroundColor Red
    Write-Log
    Write-Log "WHAT TO TRY NEXT:" -ForegroundColor Yellow
    Write-Log
    Write-Log "`t Please make sure the credentials you are providing belong to the Enterprise Administrators group." -ForegroundColor Yellow
    Write-Log
    Write-Log "---------------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Log
    Write-Log "`t Once that is done, try typing `"Start-ConnectivityValidation -Forest <Forest you desire " -ForegroundColor Yellow
    Write-Log "`t to validate> -AutoCreateConnectorAccount <`$True if you chose `"Create new AD`"" -ForegroundColor Yellow
    Write-Log "`t account in the wizard, `$False otherwise>`"`, to run all connectivity tests from the start." -ForegroundColor Yellow
    Return $False
}

# Helper function that retrieves the group Sid of the groups that a user is subscribed to.
Function GetGroupMembershipSidsForUser
{
    Write-Log "Retrieving group membership SIDs from AD"
	# Initializing list that will contain results of the search.
    $UserNestedMembership = New-Object -TypeName System.Collections.Generic.List[System.Security.Principal.SecurityIdentifier]
	$networkCredential = $Script:Credentials.GetNetworkCredential()	
	$dc = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $networkCredential.Domain, $networkCredential.UserName, $networkCredential.Password)			
	$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($dc)		
	$de = $domain.GetDirectoryEntry()

	$searchFilter = "(samAccountName=$($networkCredential.UserName))"
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($de, $searchFilter)
    $searchResult = $directorySearcher.FindOne()
	If ($null -ne $searchResult)
    {
		$UserEntry = $searchResult.GetDirectoryEntry()
		$UserEntry.RefreshCache(@("tokenGroups"))

		# Add results to previously created list.
		Foreach ($ResultBytes in $UserEntry.Properties["tokenGroups"])
		{
			$Sid = New-Object System.Security.Principal.SecurityIdentifier($ResultBytes, 0)
			$UserNestedMembership.Add($Sid)
		}
	}   
    Return $UserNestedMembership
}

<#
    .SYNOPSIS
        Retrieves a ForestFQDN out of an account and password combination.

    .DESCRIPTION
        Attempts to obtain a ForestFQDN out of the provided credentials. Account (Domain\Username) and Password
        may be requested.

    .PARAMETER Forest
        Target forest.Default value is the Domain of the currently logged in user.

    .PARAMETER RunWithCurrentlyLoggedInUserCredentials
        The function will use the credentials of the user that is currently logged in the computer, rather than
        requesting custom credentials from the user.

    .EXAMPLE
        Get-ForestFQDN -Forest CONTOSO.MICROSOFT.COM -Verbose

    .EXAMPLE
        Get-ForestFQDN -Forest CONTOSO.MICROSOFT.COM -RunWithCurrentlyLoggedInUserCredentials -Verbose
#>
Function Get-ForestFQDN
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $Forest,

        [switch] $RunWithCurrentlyLoggedInUserCredentials
    )

    Write-Log "Obtaining ForestFQDN" -ForegroundColor Yellow

        Write-Log "Using currently logged in user credentials."

        # Create object that will allow the discovery of the ForestFQDN and then attempt to retrieve it. Use currently logged in user credentials.
        $DirectoryContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("forest", $Forest)

    Write-Log "Attempting to retrieve ForestFQDN..."
    Try
    {
        $ForestFQDN = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($DirectoryContext)
    }
    Catch
    {
        Write-Log $_.Exception.Message -ForegroundColor Red
        Write-Log
        Return
    }

    # Return ForestFQDN
    Write-Log "ForestFQDN Name is: $($ForestFQDN.Name)" -ForegroundColor Green
    Return $ForestFQDN
}

<#
    .SYNOPSIS
        Validate that the domains in the obtained Forest FQDN are reachable

    .DESCRIPTION
        Validate that all of the domains in the obtained Forest FQDN are reachable by attempting
        to retrieve DomainGuid and DomainDN. Account (Domain\Username) and Password may be requested.

    .PARAMETER Forest
        Target forest.

    .PARAMETER RunWithCurrentlyLoggedInUserCredentials
        The function will use the credentials of the user that is currently logged in the computer, rather than
        requesting custom credentials from the user.

    .PARAMETER ForestFQDN
        Target ForestFQDN Object.

    .EXAMPLE
       Confirm-ValidDomains -Forest "test.contoso.com" -Verbose

    .EXAMPLE
       Confirm-ValidDomains -Forest "test.contoso.com" -RunWithCurrentlyLoggedInUserCredentials -Verbose

    .EXAMPLE
       Confirm-ValidDomains -ForestFQDN $ForestFQDN -RunWithCurrentlyLoggedInUserCredentials -Verbose

#>
Function Confirm-ValidDomains
{
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName='SamAccount')]
        [string] $Forest,

        [Parameter(ParameterSetName='ForestFQDN', Mandatory=$True)]
        [System.DirectoryServices.ActiveDirectory.Forest] $ForestFQDN,

        [switch] $RunWithCurrentlyLoggedInUserCredentials
    )

    Write-Log "Proceeding to validate that at least one of the domains associated to the obtained Forest FQDN are reachable" -ForegroundColor Yellow
    Write-Log "by attempting to retrieve DomainGuid and DomainDistinguishedName" -ForegroundColor Yellow

    $paramSetName = $PSCmdlet.ParameterSetName

    If($paramSetName -eq 'SamAccount')
    {
        If($RunWithCurrentlyLoggedInUserCredentials)
        {
            $ForestFQDN = Get-ForestFQDN -Forest $Forest -RunWithCurrentlyLoggedInUserCredentials -Verbose
        }
        Else
        {
            $ForestFQDN = Get-ForestFQDN -Forest $Forest -Verbose
        }
    }

    # Initializing the list that will contain the valid domains.
    $ReachableDomains = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $UnreachableDomains = New-Object -TypeName 'System.Collections.Generic.List[string]'

    # Traverse through all the domains in the forest do determine which are reachable.
    ForEach($Domain in $ForestFQDN.Domains)
    {
        Write-Log "Currently validating Domain: $($Domain.Name)"
        Try
        {
            # Attempt to obtain DomainGuid and DomainDistinguishedName. In case of error, the Domain is not reachable.
            $DirectoryEntry = $Domain.GetDirectoryEntry()
            $DomainGuid = $DirectoryEntry.Guid.ToString()
            $DomainDistinguishedName = $DirectoryEntry.Properties["distinguishedName"].Value.ToString()

            $Name = $DirectoryEntry.Properties["name"].Value.ToString()
            Write-Log "Using $Name to validate domain $($Domain.Name)"

            $ReachableDomains.Add($Domain)
            Write-Log "Successfully examined domain: $($Domain.Name); GUID:$DomainGuid  DN:$DomainDistinguishedName"
        }
        Catch
        {
            $UnreachableDomains.Add($Domain)
            Write-Log "Unable to reach domain: $($Domain.Name)"
        }
    }

    # Having 1 or more reachable domains is fine. Having 0 is not.
    Write-Log "There are $($ReachableDomains.Count) reachable domain(s) and $($UnreachableDomains.Count) unreachable domain(s)"

    If($ReachableDomains.Count -eq 0)
    {
        Write-Log "There are no reachable domains." -ForegroundColor Red
        Write-Log
        Return
    }
    Else
    {
        Write-Log "There are valid domains" -ForegroundColor Green
        Return $True
    }
}

<#
    .SYNOPSIS
        Verifies AD forest functional level.

    .DESCRIPTION
        Verifies that the AD forest functional level is equal or more than a given MinAdForestVersion
        (WindowsServer2003). Account (Domain\Username) and Password may be requested.

    .PARAMETER Forest
        Target forest. Default value is the Forest of the currently logged in user.

    .PARAMETER RunWithCurrentlyLoggedInUserCredentials
        The function will use the credentials of the user that is currently logged in the computer, rather than
        requesting custom credentials from the user.

    .PARAMETER ForestFQDN
        Target ForestFQDN Object.

    .EXAMPLE
        Confirm-FunctionalLevel -Forest "test.contoso.com"

    .EXAMPLE
        Confirm-FunctionalLevel -Forest "test.contoso.com" -RunWithCurrentlyLoggedInUserCredentials -Verbose

    .EXAMPLE
        Confirm-FunctionalLevel -ForestFQDN $ForestFQDN -RunWithCurrentlyLoggedInUserCredentials -Verbose
#>
Function Confirm-FunctionalLevel
{
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName='SamAccount', Mandatory=$True)]
        [string] $Forest,

        [Parameter(ParameterSetName='ForestFQDN', Mandatory=$True)]
        [System.DirectoryServices.ActiveDirectory.Forest] $ForestFQDN,

        [switch] $RunWithCurrentlyLoggedInUserCredentials
    )

    Write-Log "Verifying that the AD forest functional level is >= $MinAdForestVersion" -ForegroundColor Yellow

    $paramSetName = $PSCmdlet.ParameterSetName

    If($paramSetName -eq 'SamAccount')
    {
        If($RunWithCurrentlyLoggedInUserCredentials)
        {
            $ForestFQDN = Get-ForestFQDN -Forest $Forest -RunWithCurrentlyLoggedInUserCredentials -Verbose
        }
        Else
        {
            $ForestFQDN = Get-ForestFQDN -Forest $Forest -Verbose
        }
    }

    # Retrieve CurrentForestLevel
    $CurrentForestLevel = $ForestFQDN.ForestMode
    Write-Log "CurrentForestLevel is $CurrentForestLevel"

    # Newer versions of Windows will return a forest functional level of -1 (Unknown). In this case, we should return
    # true since it is NOT an indication that functional level is below the minimum level.
    If($CurrentForestLevel -eq -1)
    {
        Write-Log "The Active Directory forest functional level is correct" -ForegroundColor Green
        Return $True
    }

    If($CurrentForestLevel -lt $MinAdForestVersion)
    {
        Write-Log "Current forest functional level ($CurrentForestLevel) is not supported."
        Write-Log
        Write-Log "WHAT TO TRY NEXT:" -ForegroundColor Yellow
        Write-Log
        Write-Log "`t Upgrade your forest to at least $MinAdForestVersion. More information: https://go.microsoft.com/fwlink/?linkid=875541" -ForegroundColor Yellow
        Return $False
    }

    Write-Log "The Active Directory forest functional level is correct" -ForegroundColor Green
    Return $True
}

<#
    .SYNOPSIS
        Main function.

    .DESCRIPTION
        Runs all the available mechanisms that verify AD credentials are valid.

    .PARAMETER Forest
        Target forest.

    .PARAMETER AutoCreateConnectorAccount
        For Custom-installations:
            Flag that is $True if the user chose "Create new AD account" on the AD Forest Account window of AADConnect's
            wizard. $False if the user chose "Use existing AD account".
        For Express-installations:
            The value of this variable must be $True for Express-installations.

    .PARAMETER Username
        Parameter that pre-populates the Username field when user's credentials are requested.

    .PARAMETER RunWithCurrentlyLoggedInUserCredentials
        The function will use the credentials of the user that is currently logged in the computer, rather than
        requesting custom credentials from the user.

    .EXAMPLE
        Start-ConnectivityValidation -Forest "test.contoso.com" -AutoCreateConnectorAccount $True -Verbose

#>
Function Start-ConnectivityValidation
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string] $Forest,

        [Parameter(Mandatory=$True)]
        [bool] $AutoCreateConnectorAccount,

        [Parameter(Mandatory=$False)]
        [string] $UserName
    )

    Write-Log
    Write-Log
    Write-Log "Diagnosis is starting..."
    Write-Log
    Write-Progress -Activity "ADconnectivityTool" -PercentComplete (1/6 * 100)

    # Step 2 - GetDomainFQDN Name
    $DomainFQDNName = Get-DomainFQDNData -DomainFQDNDataType DomainFQDNName -Verbose
    If (-not $DomainFQDNName)
    {
        Write-Progress -Activity "ADconnectivityTool" -Completed
        Start-NetworkConnectivityDiagnosisTools -DisplayInformativeMessage -Forest $Forest
        Return
    }
    Write-Log
    Write-Log
    Write-Progress -Activity "ADconnectivityTool" -PercentComplete (2/6 * 100)

    # Step 3 - If applicable, validate the provided credentials belong to the EA group.
    If ($AutoCreateConnectorAccount)
    {
        $ValidEACredentials = Confirm-ValidEnterpriseAdminCredentials -Verbose
        If (-not $ValidEACredentials)
        {
            Write-Progress -Activity "ADconnectivityTool" -Completed
            Return
        }
    }
    Else
    {
        Write-Log "Skipping step to verify provided credentials belong to Enterprise Admins group" -ForegroundColor DarkGreen
    }
    Write-Log
    Write-Log
    Write-Progress -Activity "ADconnectivityTool" -PercentComplete (3/6 * 100)

    # Step 4 - Obtain ForestFQDN object.
    $ForestFQDN = Get-ForestFQDN -Forest $Forest -Verbose
    If (-not $ForestFQDN)
    {
        Write-Progress -Activity "ADconnectivityTool" -Completed
        Start-NetworkConnectivityDiagnosisTools -DisplayInformativeMessage -Forest $Forest
        Return
    }
    Write-Log
    Write-Log
    Write-Progress -Activity "ADconnectivityTool" -PercentComplete (4/6 * 100)

    # Step 5 - Confirm the domains associated with the ForestFQDN object are reachable.
    $ValidDomainsInForestFQDN = Confirm-ValidDomains -ForestFQDN $ForestFQDN -Verbose
    If (-not $ValidDomainsInForestFQDN)
    {
        Write-Progress -Activity "ADconnectivityTool" -Completed
        Start-NetworkConnectivityDiagnosisTools -DisplayInformativeMessage -Forest $Forest
        Return
    }
    Write-Log
    Write-Log
    Write-Progress -Activity "ADconnectivityTool" -PercentComplete (5/6 * 100)

    # Step 6 - Verify that the functional level is more or greater that the minimum required.
    $ValidFunctionalLevel = Confirm-FunctionalLevel -ForestFQDN $ForestFQDN -Verbose
    If (-not $ValidFunctionalLevel)
    {
        Write-Progress -Activity "ADconnectivityTool" -Completed
        Return
    }
    Write-Log
    Write-Log
    Write-Progress -Activity "ADconnectivityTool" -Completed

    Write-Log "ALL CONNECTIVITY TESTS HAVE PASSED. PLEASE GO BACK TO AADCONNECT INSTALLATION WIZARD AND PROVIDE YOUR CREDENTIALS AGAIN." -ForegroundColor Magenta
    Write-Log
}

#endregion

#region Global Utilities

# Auxiliary function to request username\password from the PowerShell window
Function Get-CredentialsFromPowerShellWindow
{
    Param(
        [Parameter(Mandatory=$False)]
        [string] $Message = "Retrieving user's credentials.",

        [Parameter(Mandatory=$False)]
        [string] $UserName
    )

    Write-Log $Message -ForegroundColor Yellow

    If(-not $UserName)
    {
        $UserName = Read-Host "DOMAIN\Username"
    }
    Else
    {
        Write-Log "DOMAIN\Username: $UserName  (previously obtained)"
    }
    $Password = Read-Host "Password" -AsSecureString

    $Credentials = New-Object System.Management.Automation.PSCredential ($UserName, $Password)

    Return $Credentials
}

# Function that retrieves user credentials and makes them available for the whole module.
Function Get-AccountAndPassword
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential] $Credentials
    )

    If(-not $Script:Credentials)
    {
        If($Credentials)
        {
            $Script:Credentials = $Credentials
        }
        Else
        {
            $Script:Credentials = Get-CredentialsFromPowerShellWindow
        }
    }
}

#Auxiliary Function that writes an output to a log file or the PowerShell window
Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, Position=1)]
        [string] $Message,

        [Parameter(Mandatory=$False, Position=2)]
        [string] $ForegroundColor = "Cyan"
    )
    Switch ($ForegroundColor)
    {
        Green { $Severity = "SUCCESS" }
        Red { $Severity = "ERROR  " }
        Default { $Severity = "INFO   " }
    }
    If($LogFileLocation)
    {
        If($Message -ne "")
        {
            $Message = "[" + (Get-Date).ToString() + "] [$Severity] " + $Message
            Out-File -Append -FilePath $LogFileLocation -InputObject $Message
        }
    }
    Else
    {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}

#endregion

Export-ModuleMember -Function Get-DomainFQDNData
Export-ModuleMember -Function Confirm-ValidEnterpriseAdminCredentials
Export-ModuleMember -Function Get-ForestFQDN
Export-ModuleMember -Function Confirm-ValidDomains
Export-ModuleMember -Function Confirm-FunctionalLevel
Export-ModuleMember -Function Confirm-NetworkConnectivity
Export-ModuleMember -Function Confirm-DnsConnectivity
Export-ModuleMember -Function Confirm-TargetsAreReachable
Export-ModuleMember -Function Confirm-ForestExists
Export-ModuleMember -Function Start-ConnectivityValidation
Export-ModuleMember -Function Start-NetworkConnectivityDiagnosisTools
# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDHlBFCDTniiM3d
# Th6p91lbCQCQPA91B5enUIwRIAaosKCCDXYwggX0MIID3KADAgECAhMzAAADrzBA
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOcYFb1+cOAmHbgdzjytRBqu
# hZHPIIROnm0XX3/V0LHEMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAdMKF++C0v0uNF7avyZpcggvXLGf6CYwdGCvbuSSdebegxQ/npBWU90iW
# 9j3e5/2xttyD3QMaQQc50bNQ+eMjnPrSl8rCOd/R8xgp50MQeWm0jV2ntHBzF8bs
# Qw25sNH4rFnBR432TPUO5jZ3dszc7e4sPXogNFcUEIXGUnug7plXXGpKAzjR0hb/
# iAsqCDTrt0dSFXLuy89mqAPilLijeBwSKIbbG5hUlYFrg8kHeDsk5v0rF3F0bzD5
# Gh9c3isFVLlUN/G0jRFCKBTy4PLCfxdwkzcD4STNJesjievQ15TYnljj4pd5hUzc
# KJHxsjUg+KAKYTYGCv3qhg9m/Cp846GCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAydjBjTen2Gxs/aMWBAJVJ66VPWPv+m8iGBKmdgseTGAIGZfHOIDHM
# GBMyMDI0MDMxNDIzMDMzOS4zODVaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjA4NDItNEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAHajtXJWgDREbEAAQAAAdowDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMx
# MDEyMTkwNjU5WhcNMjUwMTEwMTkwNjU5WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjowODQyLTRC
# RTYtQzI5QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJOQBgh2tVFR1j8jQA4NDf8b
# cVrXSN080CNKPSQo7S57sCnPU0FKF47w2L6qHtwm4EnClF2cruXFp/l7PpMQg25E
# 7X8xDmvxr8BBE6iASAPCfrTebuvAsZWcJYhy7prgCuBf7OidXpgsW1y8p6Vs7sD2
# aup/0uveYxeXlKtsPjMCplHkk0ba+HgLho0J68Kdji3DM2K59wHy9xrtsYK+X9er
# bDGZ2mmX3765aS5Q7/ugDxMVgzyj80yJn6ULnknD9i4kUQxVhqV1dc/DF6UBeuzf
# ukkMed7trzUEZMRyla7qhvwUeQlgzCQhpZjz+zsQgpXlPczvGd0iqr7lACwfVGog
# 5plIzdExvt1TA8Jmef819aTKwH1IVEIwYLA6uvS8kRdA6RxvMcb//ulNjIuGceyy
# kMAXEynVrLG9VvK4rfrCsGL3j30Lmidug+owrcCjQagYmrGk1hBykXilo9YB8Qyy
# 5Q1KhGuH65V3zFy8a0kwbKBRs8VR4HtoPYw9z1DdcJfZBO2dhzX3yAMipCGm6Smv
# mvavRsXhy805jiApDyN+s0/b7os2z8iRWGJk6M9uuT2493gFV/9JLGg5YJJCJXI+
# yxkO/OXnZJsuGt0+zWLdHS4XIXBG17oPu5KsFfRTHREloR2dI6GwaaxIyDySHYOt
# vIydla7u4lfnfCjY/qKTAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUoXyNyVE9ZhOV
# izEUVwhNgL8PX0UwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBALmDVdTtuI0jAEt4
# 1O2OM8CU237TGMyhrGr7FzKCEFaXxtoqk/IObQriq1caHVh2vyuQ24nz3TdOBv7r
# cs/qnPjOxnXFLyZPeaWLsNuARVmUViyVYXjXYB5DwzaWZgScY8GKL7yGjyWrh78W
# JUgh7rE1+5VD5h0/6rs9dBRqAzI9fhZz7spsjt8vnx50WExbBSSH7rfabHendpeq
# bTmW/RfcaT+GFIsT+g2ej7wRKIq/QhnsoF8mpFNPHV1q/WK/rF/ChovkhJMDvlqt
# ETWi97GolOSKamZC9bYgcPKfz28ed25WJy10VtQ9P5+C/2dOfDaz1RmeOb27Kbeg
# ha0SfPcriTfORVvqPDSa3n9N7dhTY7+49I8evoad9hdZ8CfIOPftwt3xTX2RhMZJ
# CVoFlabHcvfb84raFM6cz5EYk+x1aVEiXtgK6R0xn1wjMXHf0AWlSjqRkzvSnRKz
# FsZwEl74VahlKVhI+Ci9RT9+6Gc0xWzJ7zQIUFE3Jiix5+7KL8ArHfBY9UFLz4sn
# boJ7Qip3IADbkU4ZL0iQ8j8Ixra7aSYfToUefmct3dM69ff4Eeh2Kh9NsKiiph58
# 9Ap/xS1jESlrfjL/g/ZboaS5d9a2fA598mubDvLD5x5PP37700vm/Y+PIhmp2fTv
# uS2sndeZBmyTqcUNHRNmCk+njV3nMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjow
# ODQyLTRCRTYtQzI5QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUAQqIfIYljHUbNoY0/wjhXRn/sSA2ggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOmdna8wIhgPMjAyNDAzMTUwMDAwNDdaGA8yMDI0MDMxNjAwMDA0N1owdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA6Z2drwIBADAHAgEAAgIk8zAHAgEAAgIpJjAKAgUA
# 6Z7vLwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAKbmivNtjmPffd+eUyo1
# YT89lMaEBmsVuL2JnGNiYWqMN4KNGU1ZGs8Tvei2u8OCUPBoqA1A6zXhb5uPq3Ar
# hQGIfVCgiG3c1vQRciIXEdxGz6wqD1QSv1j/xQW70LXWCZYTwFoPJGnV+0tgpShF
# 6I/+qXLwUjzOxrApvCsDZeFiMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAHajtXJWgDREbEAAQAAAdowDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQgAnBWrDww2RudQyZ2oXc6Ct0znVaFZsESFEvrL9HZcC8wgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCAipaNpYsDvnqTe95Dj1C09020I5ljibrW/ndICOxg9
# xjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB2o7V
# yVoA0RGxAAEAAAHaMCIEIO7Z8qQNBzaCJ8SHEvdbSykTp43IzNal3+vTsAs7KrpV
# MA0GCSqGSIb3DQEBCwUABIICABlOqmQpNPBjZup5ieXPcB7cMjVgM17il2JEyjfX
# MumkN6IXV7CHA+LMbRft9NoJHQa2PzfYrVBFHjbfl86mH2r+U+0/CJgwH8Igf9VN
# iYMvBbdYkDDVxlOfND8keZscvnzaKnNWu1TUYNHpIao4JkivXJh1BQYmKW0ot+U/
# eGdkhxcW73G/63ETgN+OJogCG++yr916/Wp/1VlH1EUQNGnwLpGCB4zznM//TDsD
# zPcRhfMeg4nwisRnFFhMe7XoEnTfZtJqcKRy9z4eoHYyQ4AR2sVG677RSfPsD7B1
# +ztsWltdeVWSO4Z0/ywzPYbyd41tys+/+mm1wkKxa8Kid05XkjHaxtL7ZQNGxCD8
# ILwe2GrFfjo1KF/GRqVmtupwp3nYJPL/DlomthYqodjfYdPHhWvIK2q7imj0uqNM
# MzhA5y2mRFN7dMCGClquIjPSheU5p6Jzbh+8Kwc1MdpgOmcR2BDoDItOEfqFiQce
# cCPK5jvTRRBbtHSWjEiLCrRqrjzg1RzRzGbJ/USbfahCapW1tZm3pyNUJEJY58PP
# 6+CX7t1sLJwvR5ZHqz6F46lI6ykRLVIoojwBm8abWx89hz9bw0OtisK6D25O6aCH
# bU2mBF8m5PXEbSRWabSd97YxhmN1hjph7Omk89KTfYUra9U2C2KsayUyRM38a7D8
# RWCy
# SIG # End signature block
