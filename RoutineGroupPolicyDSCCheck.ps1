### Variables
[decimal]$WindowsVersion = (Get-WmiObject win32_operatingsystem).version.substring(0,3)
$Output = @{}
$GPOPolicyName = "Network Policy"


### Functions
function Server2012SMBSettings {
    $SMBConfiguration = Get-SmbServerConfiguration

    ### SMB Configuration Checks
    # Desired state of SMB1 is "Disabled"
    if ($SMBConfiguration.EnableSMB1Protocol -eq $false) {
        $script:Output.EnableSMB1Protocol = "Disabled"
    } elseif ($SMBConfiguration.EnableSMB1Protocol -eq $true) {
        $script:Output.EnableSMB1Protocol = "Enabled"
    } else {
        $script:Output.EnableSMB1Protocol = "Undefined"
    }

    # Desired state of SMB2 is "Enabled"
    if ($SMBConfiguration.EnableSMB2Protocol -eq $true) {
        $script:Output.EnableSMB2Protocol = "Enabled"
    } elseif ($SMBConfiguration.EnableSMB2Protocol -eq $false) {
        $script:Output.EnableSMB2Protocol = "Disabled"
    } else {
        $script:Output.EnableSMB2Protocol = "Undefined"
    }

    # Desired state of SMB EncryptData is "Enabled."
    if ($SMBConfiguration.EncryptData -eq $true) {
        $script:Output.SMBEncryptData = "Enabled"
    } elseif ($SMBConfiguration.EncryptData -eq $false) {
        $script:Output.SMBEncryptData = "Disabled"
    } else {
        $script:Output.SMBEncryptData = "Undefined"
    }
}

function Server2008SMBSettings {
    $SMBConfiguration = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
    
    # Desired state of SMB1 is "Disabled"
    if ($SMBConfiguration.SMB1 -eq 0) {
        $script:Output.EnableSMB1Protocol = "Disabled"
    } else {
        $script:Output.EnableSMB1Protocol = "Enabled"
    }

    # Desired state of SMB2 is "Enabled"
    if ($SMBConfiguration.SMB2 -eq 0) {
        $script:Output.EnableSMB2Protocol = "Disabled"
    } elseif ($SMBConfiguration.SMB2 -eq 1) {
        $script:Output.EnableSMB2Protocol = "Enabled"
    } else {
        $script:Output.EnableSMB2Protocol = "Undefined"
    }

    # Desired state of SMB EncryptData is "Enabled". This option is not available on servers older than 2012.
    $script:Output.SMBEncryptData = "Disabled"
}

function CheckIsDomainController {
    $WindowsType = (Get-WmiObject Win32_OperatingSystem).ProductType
    if ($WindowsType -eq 2) {
        return $true
    } else {
        return $false
    }
}

function CheckIfPDC {
    $hostname = hostname
    $PDCOwner = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name
    $PDCOwner = ($PDCOwner.Split('.'))[0]
    if ($PDCOwner -eq $hostname) {
	    return $true
    } else {
        Write-Output "This machine is not a PDC. Exiting script..."
        return $false
    }
}

function CheckIfSupportedWinVersion {
    if ($WindowsVersion -ge 6.0) {
        return $true
    } else {
        Write-Output "Windows version is too old. Exiting script..."
        return $false
    }
}

function GetNetworkGPOPolicy {
    try {
        # Get the GPO Guid (just like above)
        $Id = (Get-GPO -DisplayName $GPOPolicyName -ErrorAction Stop).Id
        # Store the output in a (XML) variable
        [xml]$GpoXml = Get-GPOReport -Guid $Id -ReportType Xml
    
        #Create a custom object containing only the policy "fields" we're interested in
        $script:PolicyDetails = foreach ($p in $GpoXml.GPO.Computer.ExtensionData.Extension.Policy) {
            [PSCustomObject]@{
                "Name" = $p.Name
                "State" = $p.State
                "Supported" = $p.Supported
                "Category" = $p.Category
            }
        }
    } catch {
        $script:PolicyDetails = "None"
    }
}

function IsMulticastDisabledInReg {
    # If there isn't a GPO policy setting "Turn off multicast name resolution" to Enabled, there are two registry keys that could
    # produce the same effect. If both of them are set properly, LLMNR and NBT-NS will be disabled.
    # Desired state is "Disabled." Refer to CheckDisableMulticast function for more information.
    try {
        $LLMNRReg = Get-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -ErrorAction Stop
        if ($LLMNRReg.EnableMulticast -eq 0) {
            $NBTNSPath = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
            Get-ChildItem $NBTNSPath | ForEach-Object { 
                $CurrentNBTNS = Get-ItemProperty -Path "$NBTNSPath\$($_.pschildname)"
                
                if ($CurrentNBTNS.NetbiosOptions -ne 2) {
                    return "Enabled"
                    break
                } 
            }
            return "Disabled"
        } else {
            return "Enabled"
        }
    } catch {
        return "Enabled"
    }
}

function CheckServerRequireSecuritySignature {
    # Microsoft network server: Digitally sign communications (always)
    # Desired state is "Enabled"
    if ($SMBServerParameters.requiresecuritysignature -eq 1) {
        return "Enabled"
    } elseif ($SMBServerParameters.requiresecuritysignature -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckServerEnableSecuritySignature {
    # Microsoft network server: Digitally sign communications (if client agrees)
    # Desired state is "Enabled"
    if ($SMBServerParameters.enablesecuritysignature -eq 1) {
        return "Enabled"
    } elseif ($SMBServerParameters.enablesecuritysignature -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckClientRequireSecuritySignature {
    # Microsoft network client: Digitally sign communications (always)
    # Desired state is "Enabled"
    if ($SMBWorkstationParameters.requiresecuritysignature -eq 1) {
        return "Enabled"
    } elseif ($SMBWorkstationParameters.requiresecuritysignature -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckClientEnableSecuritySignature {
    # Microsoft network client: Digitally sign communications (if server agrees)
    # Desired state is "Enabled"
    if ($SMBWorkstationParameters.enablesecuritysignature -eq 1) {
        return "Enabled"
    } elseif ($SMBWorkstationParameters.enablesecuritysignature -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckRestrictAnonymousSAM {
    # Network access: Do not allow anonymous enumeration of SAM accounts
    # Desired state is "Enabled"
    if ($LsaRegKey.RestrictAnonymousSAM -eq 1) {
        return "Enabled"
    } elseif ($LsaRegKey.RestrictAnonymousSAM -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckRestrictAnonymous {
    # Network access: Do not allow anonymous enumeration of SAM accounts and shares
    # Desired state is "Enabled"
    if ($LsaRegKey.RestrictAnonymous -eq 1) {
        return "Enabled"
    } elseif ($LsaRegKey.RestrictAnonymous -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckNullSessionShares {
    # Network access: Restrict anonymous access to Named Pipes and Shares
    # Desired state is "Enabled"
    if ($SMBServerParameters.NullSessionShares -eq 1) {
        return "Enabled"
    } elseif ($SMBServerParameters.NullSessionShares -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckNoLMHash {
    # Network security: Do not store LAN Manager hash value on next password change
    # Desired state is "Enabled"
    if ($LsaRegKey.NoLMHash -eq 1) {
        return "Enabled"
    } elseif ($LsaRegKey.NoLMHash -eq 0) {
        return "Disabled" 
    } else {
        return "Undefined"
    }
}

function CheckLmCompatibilityLevel {
    # Network security: LAN Manager authentication level
    # Desired state is 5
    if ($LsaRegKey.LmCompatibilityLevel) {
        return $LsaRegKey.LmCompatibilityLevel
    } else {
        return "Undefined"
    }
}

function CheckRequireSignOrSeal {
    # Domain member: Digitally encrypt or sign secure channel data (always)
    # Desired state is "Enabled"
    if ($NetlogonParameters.RequireSignOrSeal -eq 1) {
        return "Enabled"
    } elseif ($NetlogonParameters.RequireSignOrSeal -eq 0) {
        return "Disabled" 
    } else {
        return "Undefined"
    }
}

function CheckSupportedEncryptionTypes {
    # Network security: Configure encryption types allowed for Kerberos
    # Desired state is 2147483640 (decimal) or 7ffffff8 (hex)
    if ($KerberosParameters.SupportedEncryptionTypes) {
        return $KerberosParameters.SupportedEncryptionTypes
    } else {
        return "Undefined"
    }
}

function CheckDisableMulticast {
    # Network/DNS Client: Turn off multicast name resolution
    # The wording on this policy is different between GPO and registry keys. 
    # If multicast name resolution is disabled by either GPO or registry key, it will be considered "Disabled." This is the desired state.
    $DisableMulticastNameResolution = ($PolicyDetails | Where-Object { $_.Name -eq "Turn off multicast name resolution" }).State

    if ($DisableMulticastNameResolution -eq "Enabled") {
        return "Disabled"
    } else {
        return IsMulticastDisabledInReg
    }
}

function CheckRequireSecureRPC {
    # Windows Components/Remote Desktop Services/Remote Desktop Session Host/Security: Require secure RPC communication
    # Desired state is "Enabled"
    $RequireSecureRPC = ($PolicyDetails | Where-Object { $_.Name -eq "Require secure RPC communication" }).State

    if ($RequireSecureRPC -eq "Enabled") {
        return "Enabled"
    } elseif ($RequireSecureRPC -eq "Disabled") {
        return "Disabled"
    } else {
        if ($TerminalServicesRegKey.fEncryptRPCTraffic -eq 1) {
            return "Enabled"
        } elseif ($TerminalServicesRegKey.fEncryptRPCTraffic -eq 0) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckRequireSecurityLayerRDP {
    # Windows Components/Remote Desktop Services/Remote Desktop Session Host/Security: Require use of specific security layer for remote (RDP) connections
    # The value of this registry key could be 0, 1, or 2. SSL is only required if the registry key's value is 2. 
    # Because of this, if the key's value is 2, we will consider this property to be "Enabled." This is the desired state.
    $RequireSecurityLayerRDP = ($PolicyDetails | Where-Object { $_.Name -eq "Require use of specific security layer for remote (RDP) connections" }).State

    if ($RequireSecurityLayerRDP -eq "Enabled") {
        return "Enabled"
    } else {
        if ($TerminalServicesRegKey.SecurityLayer -eq 2) {
            return "Enabled"
        } elseif ($TerminalServicesRegKey.SecurityLayer) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckSetClientConnectEncryptLevel {
    # Windows Components/Remote Desktop Services/Remote Desktop Session Host/Security: Set client connection encryption level
    # The value of this registry key could be 1, 2, or 3. Desired state is 3. 
    # Because of this, if the key's value is 3, we will consider this property to be "Enabled." This is the desired state.
    $SetClientConnectEncryptLevel = ($PolicyDetails | Where-Object { $_.Name -eq "Set client connection encryption level"}).StartName

    if ($SetClientConnectEncryptLevel -eq "Enabled") {
        return "Enabled"
    } else {
        if ($TerminalServicesRegKey.MinEncryptionLevel -eq 3) {
            return "Enabled"
        } elseif ($TerminalServicesRegKey.MinEncryptionLevel) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckAllowBasicAuthClient {
    # Windows Components/Windows Remote Management (WinRM)/WinRM Client: Allow Basic authentication 
    # If this property is disabled or not configured, WinRM client does not use basic authentication
    # Desired state is "Disabled" even though "Undefined" would produce the same functional result
    $AllowBasicAuthClient = ($PolicyDetails | Where-Object { ($_.Name -eq "Allow Basic authentication") -AND ($_.Category -eq "Windows Components/Windows Remote Management (WinRM)/WinRM Client")}).State

    if ($AllowBasicAuthClient -eq "Disabled") {
        return "Disabled"
    } else {
        if ($WinRMClientRegKey.AllowBasic -eq 1) {
            return "Enabled"
        } elseif ($WinRMClientRegKey.AllowBasic -eq 0) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckDisallowDigestAuth {
    # Windows Components/Windows Remote Management (WinRM)/WinRM Client: Disallow Digest authentication
    # Though the GPO uses the term "disallow", the registry key uses the term "allow".
    # Because of this, if the registry key is explicitly set to 0, we will consider DisallowDigestAuth to be "Enabled." This is the desired state.
    $DisallowDigestAuth = ($PolicyDetails | Where-Object { $_.Name -eq "Disallow Digest authentication" }).State

    if ($DisallowDigestAuth -eq "Enabled") {
        return "Enabled"
    } else {
        if ($WinRMClientRegKey.AllowDigest -eq 0) {
            return "Enabled"
        } elseif ($WinRMClientRegKey.AllowDigest -eq 1) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckAllowBasicAuthService {
    # Windows Components/Windows Remote Management (WinRM)/WinRM Service: Allow Basic authentication 
    # If this property is disabled or not configured, WinRM service does not use basic authentication
    # Desired state is "Disabled" even though "Undefined" would produce the same functional result
    $AllowBasicAuthClient = ($PolicyDetails | Where-Object { ($_.Name -eq "Allow Basic authentication") -AND ($_.Category -eq "Windows Components/Windows Remote Management (WinRM)/WinRM Service")}).State

    if ($AllowBasicAuthClient -eq "Disabled") {
        return "Disabled"
    } else {
        if ($WinRMServiceRegKey.AllowBasic -eq 1) {
            return "Enabled"
        } elseif ($WinRMServiceRegKey.AllowBasic -eq 0) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckAllowUnencryptedTraffic {
    # Windows Components/Windows Remote Management (WinRM)/WinRM Service: Allow unencrypted traffic
    # If this property is disabled or not configured, WinRM service does not send or receive unencrypted messages
    # Desired state is "Disabled" even though "Undefined" would produce the same functional result
    $AllowUnencryptedTraffic = ($PolicyDetails | Where-Object { $_.Name -eq "Allow unencrypted traffic" }).State

    if ($AllowUnencryptedTraffic -eq "Disabled") {
        return "Disabled"
    } else {
        if ($WinRMServiceRegKey.AllowUnencryptedTraffic -eq 1) {
            return "Enabled"
        } elseif ($WinRMServiceRegKey.AllowUnencryptedTraffic -eq 0) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckDisallowWinRMStoreRunAs {
    # Windows Components/Windows Remote Management (WinRM)/WinRM Service: Disallow WinRM from storing RunAs credentials
    # Desired state is "Enabled", meaning that WinRM is disallowed from storing RunAs credentials
    $DisallowWinRMStoreRunAs = ($PolicyDetails | Where-Object { $_.Name -eq "Disallow WinRM from storing RunAs credentials" }).State

    if ($DisallowWinRMStoreRunAs -eq "Enabled") {
        return "Enabled"
    } else {
        if ($WinRMServiceRegKey.DisableRunAs -eq 1) {
            return "Enabled"
        } elseif ($WinRMServiceRegKey.DisableRunAs -eq 0) {
            return "Disabled"
        } else {
            return "Undefined"
        }
    }
}

function CheckDisabledComponents {
    # Preferences/Windows Settings/Registry: Disabled Components
    # Desired state is 255
    if ($TCPv6Parameters.DisabledComponents) {
        return $TCPv6Parameters.DisabledComponents
    } else {
        return "Undefined"
    }
}

function CheckLocalAccountTokenFilterPolicy {
    # Preferences/Windows Settings/Registry: LocalAccountTokenFilterPolicy
    # Desired state is "Enabled"
    if ($SystemPoliciesRegKey.LocalAccountTokenFilterPolicy -eq 1) {
        return "Enabled"
    } elseif ($SystemPoliciesRegKey.LocalAccountTokenFilterPolicy -eq 0) {
        return "Disabled"
    } else {
        return "Undefined"
    }
}

function CheckCredentialGuard {
    # Computer Configuration/Administrative Templates/System/Device Guard/Turn On Virtualization Based Security/Credential Guard Configuration
    # 1 = Windows Defender Credential Guard with UEFI lock, 2 = Windows Defender Credential Guard without lock, 0 = Disabled
    # Desired state is 1
    if ($LsaRegKey.LsaCfgFlags) {
        return $LsaRegKey.LsaCfgFlags
    } else {
        return "Undefined"
    }
}

function CheckAllowNullSessionFallback {
    # Network Security: Allow local System NULL session fallback
    # Desired state is "Disabled"
    if ($MSV10.allownullsessionfallback) {
        if ($MSV10.allownullsessionfallback -eq 0) {
            return "Disabled"
        } else {
            return "Enabled"
        }
    } else {
        return "Undefined"
    }
}


### Code logic

# Check to see if the machine is performing the PDC Emulator FSMO role and that it's running Windows Server 2008 or greater
# If not, exit script
$IsSupportedWinVersion = CheckIfSupportedWinVersion

$IsDomainController = CheckIsDomainController

if ($IsDomainController) {
    $Output.IsPDC = CheckIfPDC
} else {
    $Output.IsPDC = $false
}

if ($IsSupportedWinVersion -eq $false) {
    exit
}

if ($WindowsVersion -ge 6.2) {
    Server2012SMBSettings
} else {
    Server2008SMBSettings
}

$SMBServerParameters = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -ErrorAction SilentlyContinue
$SMBWorkstationParameters = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManWorkStation\Parameters -ErrorAction SilentlyContinue
$LsaRegKey = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa -ErrorAction SilentlyContinue
$MSV10 = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0 -ErrorAction SilentlyContinue
$NetlogonParameters = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -ErrorAction SilentlyContinue
$KerberosParameters = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters -ErrorAction SilentlyContinue
$TerminalServicesRegKey = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
$WinRMClientRegKey = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -ErrorAction SilentlyContinue
$WinRMServiceRegKey = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -ErrorAction SilentlyContinue
$TCPv6Parameters = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -ErrorAction SilentlyContinue
$SystemPoliciesRegKey = Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -ErrorAction SilentlyContinue

GetNetworkGPOPolicy

# Microsoft network server: Digitally sign communications (always)
$Output.ServerRequireSecuritySignature = CheckServerRequireSecuritySignature

# Microsoft network server: Digitally sign communications (if client agrees)
$Output.ServerEnableSecuritySignature = CheckServerEnableSecuritySignature

# Microsoft network client: Digitally sign communications (always)
$Output.ClientRequireSecuritySignature = CheckClientRequireSecuritySignature

# Microsoft network client: Digitally sign communications (if server agrees)
$Output.ClientEnableSecuritySignature =  CheckClientEnableSecuritySignature

# Network access: Do not allow anonymous enumeration of SAM accounts
$Output.RestrictAnonymousSAM = CheckRestrictAnonymousSAM

# Network access: Do not allow anonymous enumeration of SAM accounts and shares
$Output.RestrictAnonymous = CheckRestrictAnonymous

# Network access: Restrict anonymous access to Named Pipes and Shares
$Output.NullSessionShares = CheckNullSessionShares

# Network security: Do not store LAN Manager hash value on next password change
$Output.NoLMHash = CheckNoLMHash

# Network security: LAN Manager authentication level
$Output.LmCompatibilityLevel = CheckLmCompatibilityLevel

# Domain member: Digitally encrypt or sign secure channel data (always)
$Output.RequireSignOrSeal = CheckRequireSignOrSeal

# Network security: Configure encryption types allowed for Kerberos
$Output.SupportedEncryptionTypes = CheckSupportedEncryptionTypes

# Network/DNS Client: Turn off multicast name resolution
$Output.DisableMulticast = CheckDisableMulticast

# Windows Components/Remote Desktop Services/Remote Desktop Session Host/Security: Require secure RPC communication
$Output.RequireSecureRPC = CheckRequireSecureRPC

# Windows Components/Remote Desktop Services/Remote Desktop Session Host/Security: Require use of specific security layer for remote (RDP) connections
$Output.RequireSecurityLayerRDP = CheckRequireSecurityLayerRDP

# Windows Components/Remote Desktop Services/Remote Desktop Session Host/Security: Set client connection encryption level
$Output.SetClientConnectEncryptLevel = CheckSetClientConnectEncryptLevel

# Windows Components/Windows Remote Management (WinRM)/WinRM Client: Allow Basic authentication 
$Output.AllowBasicAuthClient = CheckAllowBasicAuthClient

# Windows Components/Windows Remote Management (WinRM)/WinRM Client: Disallow Digest authentication
$Output.DisallowDigestAuth = CheckDisallowDigestAuth

# Windows Components/Windows Remote Management (WinRM)/WinRM Service: Allow Basic authentication
$Output.AllowBasicAuthService = CheckAllowBasicAuthService

# Windows Components/Windows Remote Management (WinRM)/WinRM Service: Allow unencrypted traffic
$Output.AllowUnencryptedTraffic = CheckAllowUnencryptedTraffic

# Windows Components/Windows Remote Management (WinRM)/WinRM Service: Disallow WinRM from storing RunAs credentials
$Output.DisallowWinRMStoreRunAs = CheckDisallowWinRMStoreRunAs

# Preferences/Windows Settings/Registry: Disabled Components
$Output.DisabledComponents = CheckDisabledComponents

# Preferences/Windows Settings/Registry: LocalAccountTokenFilterPolicy
$Output.LocalAccountTokenFilterPolicy = CheckLocalAccountTokenFilterPolicy

# Computer Configuration/Administrative Templates/System/Device Guard/Turn On Virtualization Based Security/Credential Guard Configuration
$Output.CredentialGuard = CheckCredentialGuard

# Network Security: Allow local System NULL session fallback
$Output.AllowNullSessionFallback = CheckAllowNullSessionFallback


if ($IsDomainController) {
    Import-Module ActiveDirectory
    $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy

    ### Password Policy Checks
    $Output.PasswordLength = $PasswordPolicy.MinPasswordLength
    $Output.PasswordExpiration = $PasswordPolicy.MaxPasswordAge
    if ($PasswordPolicy.ComplexityEnabled -eq $true) {
        $Output.PasswordComplexity = "Enabled"
    } elseif ($PasswordPolicy.ComplexityEnabled -eq $false) {
            $Output.PasswordComplexity = "Disabled"
    } else {
        $Output.PasswordComplexity = "Undefined"
    }
    if ($PasswordPolicy.ReversibleEncryptionEnabled -eq $true) {
        $Output.ReversibleEncryptionEnabled = "Enabled"
    } elseif ($PasswordPolicy.ReversibleEncryptionEnabled -eq $false) {
        $Output.ReversibleEncryptionEnabled = "Disabled"
    } else {
        $Output.ReversibleEncryptionEnabled = "Undefined"
    }
} else {
    $Output.PasswordLength = "Undefined"
    $Output.PasswordComplexity = "Undefined"
    $Output.PasswordExpiration = "Undefined"
    $Output.ReversibleEncryptionEnabled = "Undefined"
}

$Final = [string]::Join("|",($Output.GetEnumerator() | ForEach-Object { $_.Name + "=" + $_.Value }))
Write-Output $Final