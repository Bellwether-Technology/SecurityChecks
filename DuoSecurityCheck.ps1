### Declare variables
$Alert = 0
$DuoServiceAccountName = "@DuoServiceAccountName@"

$DuoVersion = "@DuoVersion@"
$DuoVersionSplit = ($DuoVersion.Split('.'))[0]
if ([System.Int32]::Parse($DuoVersionSplit) -ge 5) {
    $DuoConfigPath = "C:\Program Files\Duo Security Authentication Proxy\"
} else {
    $DuoConfigPath = "C:\Program Files (x86)\Duo Security Authentication Proxy\"
}

$ConfigFileContent = Get-Content "$DuoConfigPath\conf\authproxy.cfg"

### Functions

function IsDuoRunning {
	try {
		$DuoServiceStatus = (Get-Service duoauthproxy).Status

		if (!$DuoServiceStatus) {
			Write-Output "Duo service can not be found. It does not appear to be installed properly."
			$script:Alert = 1
		} elseif ($DuoServiceStatus -eq "Running") {
			Write-Output "Duo service is running."	
		} else {
			Write-Output "Duo service is not running."
			$script:Alert = 1
		}
	} catch {
		Write-Output "Error getting Duo service (duoauthproxy) status."
		$script:Alert = 1
	}

	try {		
		$DuoProcess = Get-Process proxy_svc

		if (!$DuoProcess) {
			Write-Output "Duo process is not running."
			$script:Alert = 1
		} else {
			Write-Output "Duo process is running."
		}
	} catch {
		Write-Output "Error getting Duo process (proxy_svc) status."
		$script:Alert = 1
	}
}

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
    } elseif ($SkeySetting) {
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

function CheckLogServiceUser {
	$garbage,$ServiceUsername = ($ConfigFileContent | Where-Object { $_ -match "service_account_username" }) -split ('=') -replace (' ','')

	if ($ServiceUsername -eq $DuoServiceAccountName) {
		Write-Output "Duo's authproxy.cfg is using the correct AD account."
	} elseif ($ServiceUsername) {
		Write-Output "Duo authproxy.cfg does not appear to be using the correct AD account. This should be set as the service account granted least privilege."
	} else {
		Write-Output "Error finding Duo service account setting in authproxy.cfg."
	}
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
		$LogDirPermissionsCheck = $LogDirPermissions | Where-Object { ($_.FileSystemRights -eq "Modify, Synchronize") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$LogDirPermissionsCheck) {
			Write-Output "$DuoServiceAccountName user does have permissions to the log directory but they are not sufficient. Please adjust."
			$script:Alert = 1
		} else {
			Write-Output "$DuoServiceAccountName has appropriate permissions to the log directory."
		}
	}
	
	### Check conf directory permissions
	$ConfDirPermissions = (Get-Acl "$DuoConfigPath\conf").Access | 
							Where-Object { $_.IdentityReference -like "*\$DuoServiceAccountName" }

	if (!$ConfDirPermissions) {
		Write-Output "$DuoServiceAccountName user does not have permissions to the log directory."
		$script:Alert = 1
	} else {
		$ConfDirPermissionsCheck = $ConfDirPermissions | Where-Object { ($_.FileSystemRights -eq "ReadAndExecute, Synchronize") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$ConfDirPermissionsCheck) {
			Write-Output "$DuoServiceAccountName user does have permissions to the conf directory but they are not sufficient. Please adjust."
			$script:Alert = 1
		} else {
			Write-Output "$DuoServiceAccountName has appropriate permissions to the conf directory."
		}
	}
	
	### Check ProgramData directory permissions
	$ProgramDataPermissions = (Get-Acl "C:\ProgramData\Duo Authentication Proxy").Access | 
							Where-Object { $_.IdentityReference -like "*\$DuoServiceAccountName" }

	if (!$ProgramDataPermissions) {
		Write-Output "$DuoServiceAccountName user does not have permissions to the Duo directory in ProgramData."
		$script:Alert = 1
	} else {
		$ProgramDataPermissionsCheck = $ProgramDataPermissions | Where-Object { ($_.FileSystemRights -eq "Modify, Synchronize") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$ProgramDataPermissionsCheck) {
			Write-Output "$DuoServiceAccountName user does have permissions to the Duo directory in ProgramData but they are not sufficient. Please adjust."
			$script:Alert = 1
		} else {
			Write-Output "$DuoServiceAccountName has appropriate permissions to the Duo directory in ProgramData."
		}
	}
}

function TestDuoConnectivityTool {
	try {    
		$ConnectivityTool = & "$DuoConfigPath\bin\authproxy_connectivity_tool.exe"
		$ConnectivityToolErrors = 0
		$ConnectivityValidationErrors = 0
	
		if ($ConnectivityTool) {
			$ConnectivityTool | ForEach-Object {
				if ($_ -match "\[error\]") {
					$ConnectivityToolErrors = 1
					if ($_ -match "\[error\] Configuration validation was not successful") {
						$ConnectivityValidationErrors = 1
					}
				}
			}
	
			if ($ConnectivityToolErrors -eq 1) {
			   $script:Alert = 1
				Write-Output "Duo Connectivity Tool found configuration errors"
				if ($ConnectivityValidationErrors -eq 1) {
					Write-Output "Duo Connectivity Tool reported that configuration validation was not successful."
				}
			} else {
				Write-Output "Duo Connectivity Tool reported no errors."
			}
		} else {
			$script:Alert = 1
			Write-Output "Duo Connectivity Tool produced no output."
		}
	} catch {
		$script:Alert = 1
		Write-Output "Error running Duo Connectivity Tool"
	}	
}


### Code logic

IsDuoRunning
CheckFailMode
CheckSkeyProtect
CheckLDAPS ### TODO
CheckLogServiceUser
CheckServiceRunAsUser ### If this function finds the service running at the correct user, it will check for least privileges
TestDuoConnectivityTool