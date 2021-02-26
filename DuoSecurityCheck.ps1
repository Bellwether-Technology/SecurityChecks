### Declare variables
$Alert = 0
$DuoServiceAccountName = "DuoServiceAccount"

$DuoVersion = "@DuoVersion@"
$DuoVersionSplit = ($DuoVersion.Split('.'))[0]
if ([System.Int32]::Parse($DuoVersionSplit) -ge 5) {
    $DuoConfigPath = "C:\Program Files\Duo Security Authentication Proxy\"
} else {
    $DuoConfigPath = "C:\Program Files (x86)\Duo Security Authentication Proxy\"
}

$ConfigFileContent = Get-Content "$DuoConfigPath\conf\authproxy.cfg"


### Functions

function CheckFailMode {
	### Change or alert of "safe" instead of "secure"
    $FailSafe = $ConfigFileContent | Where-Object { $_ -match "failmode" }

    if ($FailSafe -like "failmode*=*secure") {
        Write-Output "Failsafe is properly configured (secure)."
    } elseif ($FailSafe -like "failmode*=*safe") {
        Write-Output 'Failsafe is currently configured to "safe" but needs to be changed to "secure".'
        $script:Alert = 1
    } else {
        Write-Output "Failsafe configuration could not be parsed."
        $script:Alert = 1
    }
}

function CheckSkeyProtect {
	### Alert if Skey is not protected

	### Change or alert of "safe" instead of "secure"
    $SkeySetting = $ConfigFileContent | Where-Object { $_ -match "skey" }

    if ($SkeySetting -match "skey_protected") {
        Write-Output "skey is properly configured (protected)."
    } elseif ($SkeySetting -like "skey*=") {
        Write-Output 'skey is not secured. skey needs to be protected.'
        $script:Alert = 1
    } else {
        Write-Output "skey configuration could not be parsed."
        $script:Alert = 1
    }
}

function CheckLDAPS {
	### Alert if using LDAP instead of LDAPS
}

function CheckServiceRunAsUser {
	### Alert if service is running as LocalSystem or if user is domain admin
    $script:RunningAsServiceAccount = (Get-CimInstance Win32_Service -Filter "Name like 'duoauthproxy'").StartName

	if ($RunningAsServiceAccount -ne $DuoServiceAccountName) {
		Write-Output "DuoAuthProxy is running as $RunningAsServiceAccount. Duo should be setup with a service account configured with least privilege."
		$script:Alert = 1
	} else {
		CheckServiceAccountPermissions
	}
}

function CheckServiceAccountPermissions {
	### Least privileges for a DuoServiceAccount are:
	### 	Full Control to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\DuoAuthProxy
	### 	Modify to C:\Program Files\Duo Security Authentication Proxy\log
	### 	Read & Execute, List folder contents, and Read under Advanced Security settings to C:\Program Files\Duo Authentication Proxy\conf
	### 	Modify under Advanced Security settings to C:\ProgramData\Duo Authentication Proxy

	### Check registry key permissions
	$RegKeyPermissions = (Get-Acl HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\DuoAuthProxy).Access | 
							Where-Object { $_.IdentityReference -like "*\$DuoServiceAccountName" }

	if (!$RegKeyPermissions) {
		Write-Output "$DuoServiceAccountName user does not have permissions to relevant registry key."
		$script:Alert = 1
	} else {
		$RegKeyPermissionsCheck = $RegKeyPermissions | Where-Object { ($_.RegistryRights -eq "FullControl") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$RegKeyPermissionsCheck) {
			Write-Output "$DuoServiceAccountName user does have permissions to relevant registry key but they are not sufficient. Please adjust."
			$script:Alert = 1
		} else {
			Write-Output "$DuoServiceAccountName has appropriate permissions to the relevant registry key."
		}
	}
	
	### Check log directory permissions
	$LogDirPermissions = (Get-Acl "$DuoConfigPath\log").Access | 
							Where-Object { $_.IdentityReference -like "*\$DuoServiceAccountName" }

	if (!$LogDirPermissions) {
		Write-Output "$DuoServiceAccountName user does not have permissions to the log directory."
		$script:Alert = 1
	} else {
		$LogDirPermissionsCheck = $LogDirPermissions | Where-Object { ($_.FileSystemRights -like "*Modify*") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$LogDirPermissionsCheck) {
			Write-Output "$DuoServiceAccountName user does have permissions to the log directory but they are not sufficient. Please adjust."
			$script:Alert = 1
		} else {
			Write-Output "$DuoServiceAccountName has appropriate permissions to the log directory."
		}
	}
	
	### Check conf directory permissions
	
	### Check ProgramData directory permissions
	
}

function CheckSyncStatus {
	### Find a way to see if there are communication errors
    # $AuthProxyLogLastFiveLines = Get-Content -Path "$DuoConfigPath\log\authproxy.log" -Tail 5
    # Need to consider how to adequately determine if Duo is communicating.
}


### Code logic

CheckFailMode
CheckSkeyProtect
CheckLDAPS
CheckServiceRunAsUser ### If this function finds the service running at the correct user, it will check for least privileges
CheckSyncStatus