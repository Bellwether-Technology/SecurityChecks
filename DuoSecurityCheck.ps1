### Declare variables
$OutputValues = @{} ### Value of 1 denotes proper configuration (except for Alert)
$OutputValues.Alert = 0
$OutputValues.LogOutput = @()
$OutputValues.AccountPermission = 1

$ErrorActionPreference = "SilentlyContinue"

$DuoServiceAccountName = "@DuoServiceAccountName@"
if ($DuoServiceAccountName.Contains("\")) {
	$garbage,$DuoServiceAccountNoDomain = $DuoServiceAccountName -Split '\\'
} else {
	$DuoServiceAccountNoDomain = $DuoServiceAccountName
}

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
			$script:OutputValues.LogOutput += "Duo service can not be found. It does not appear to be installed properly."
			$script:OutputValues.Alert = 1
		} elseif ($DuoServiceStatus -eq "Running") {
			$script:OutputValues.LogOutput += "Duo service is running."	
		} else {
			$script:OutputValues.LogOutput += "Duo service is not running."
			$script:OutputValues.Alert = 1
		}
	} catch {
		$script:OutputValues.LogOutput += "Error getting Duo service (duoauthproxy) status."
		$script:OutputValues.Alert = 1
	}

	try {		
		$DuoProcess = Get-Process proxy_svc

		if (!$DuoProcess) {
			$script:OutputValues.LogOutput += "Duo process is not running."
			$script:OutputValues.Alert = 1
		} else {
			$script:OutputValues.LogOutput += "Duo process is running."
		}
	} catch {
		$script:OutputValues.LogOutput += "Error getting Duo process (proxy_svc) status."
		$script:OutputValues.Alert = 1
	}
}

function CheckFailMode {
	### Change or alert of "safe" instead of "secure"
    $FailSafe = $ConfigFileContent | Where-Object { $_ -match "failmode" }

    if ($FailSafe -like "failmode*=*secure") {
        $script:OutputValues.LogOutput += "Failmode is properly configured (secure)."
		$script:OutputValues.FailMode = 1
    } elseif ($FailSafe -like "failmode*=*safe") {
        $script:OutputValues.LogOutput += 'Failmode is currently configured to "safe" but needs to be changed to "secure".'
        $script:OutputValues.Alert = 1
		$script:OutputValues.FailMode = 0
    } else {
        $script:OutputValues.LogOutput += "Failmode configuration could not be parsed."
        $script:OutputValues.Alert = 1
		$script:OutputValues.FailMode = 0
    }
}

function CheckAllKeysProtected {
	### Alert if Skey is not protected

	### Change or alert of "safe" instead of "secure"
    $SkeySetting = $ConfigFileContent | Where-Object { $_ -match "skey" }
	$ServicePass = $ConfigFileContent | Where-Object { $_ -match "service_account_password" }
	$RadiusSecret = $ConfigFileContent | Where-Object { $_ -match "radius_secret"}

    if (($SkeySetting -match "skey_protected") -AND ($ServicePass -match "service_account_password_protected") -AND ($RadiusSecret -match "radius_secret_protected")) {
        $script:OutputValues.LogOutput += "All keys are properly configured (protected)."
		$script:OutputValues.AllKeysProtected = 1
    } elseif ($SkeySetting) {
        $script:OutputValues.LogOutput += 'Not all keys are secured. Service account password, skey,and RADIUS secret all need to be protected.'
        $script:OutputValues.Alert = 1
		$script:OutputValues.AllKeysProtected = 0
    } else {
        $script:OutputValues.LogOutput += "Key configuration could not be parsed."
        $script:OutputValues.Alert = 1
		$script:OutputValues.AllKeysProtected = 0
    }
}

function CheckLDAPS {
    ### Alert if using LDAP instead of LDAPS
    $LDAPSSetting = $ConfigFileContent | Where-Object { $_ -match "transport" }

    if ($LDAPSSetting -like "transport*=*ldaps") {
        $script:OutputValues.LogOutput += 'LDAPS is in use.'
	$script:OutputValues.LDAPSInUse = 1
    } elseif ($SkeySetting) {
        $script:OutputValues.LogOutput += 'LDAPS is not in use. Check LDAPS cert and set LDAPS in config.'
        $script:OutputValues.Alert = 1
	$script:OutputValues.LDAPSInUse = 0
    } else {
        $script:OutputValues.LogOutput += "LDAPS configuration could not be parsed. From config file: $LDAPSSetting"
        $script:OutputValues.Alert = 1
	$script:OutputValues.LDAPSInUse = 0
    }
}

function CheckSecurityGroup {
	$SecurityGroup = $ConfigFileContent | Where-Object { $_ -match "security_group_dn" }

	if ($SecurityGroup) {
        $script:OutputValues.LogOutput += 'AD security group is specified in config.'
		$script:OutputValues.SecurityGroup = 1
    } else {
		$LDAPFilter = $ConfigFileContent | Where-Object { $_ -match "ldap_filter" }
		if ($LDAPFilter) {
			$script:OutputValues.LogOutput += 'AD security group is specified in config using LDAP filter.'
			$script:OutputValues.SecurityGroup = 1
		} else {
			$script:OutputValues.LogOutput += 'No AD security group specified in config.'
			$script:OutputValues.Alert = 1
			$script:OutputValues.SecurityGroup = 0
		}
	}

}

function CheckLogServiceUser {
	$garbage,$ServiceUsername = ($ConfigFileContent | Where-Object { $_ -match "service_account_username" }) -split ('=') -replace (' ','')

	if ($ServiceUsername -eq $DuoServiceAccountNoDomain) {
		$script:OutputValues.LogOutput += "Duo's authproxy.cfg is using the correct AD account."
		$script:OutputValues.ConfigFileServiceUser = 1
	} elseif ($ServiceUsername) {
		$script:OutputValues.LogOutput += "Duo authproxy.cfg does not appear to be using the correct AD account. This should be set as the service account granted least privilege."
		$script:OutputValues.ConfigFileServiceUser = 0
	} else {
		$script:OutputValues.LogOutput += "Error finding Duo service account setting in authproxy.cfg."
		$script:OutputValues.ConfigFileServiceUser = 0
	}
}

function CheckServiceRunAsUser {
	### Alert if service is running as LocalSystem or if user is domain admin
    $script:RunningAsServiceAccount = (Get-CimInstance Win32_Service -Filter "Name like 'duoauthproxy'").StartName

	if ($RunningAsServiceAccount -notmatch $DuoServiceAccountNoDomain) {
		$script:OutputValues.LogOutput += "DuoAuthProxy is running as $RunningAsServiceAccount. Duo should be setup with a service account configured with least privilege."
		$script:OutputValues.ServiceRunAsUser = 0
		$script:OutputValues.Alert = 1
	} else {
		$script:OutputValues.LogOutput += "DuoAuthProxy is running as the correct service account."
		$script:OutputValues.ServiceRunAsUser = 1
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
							Where-Object { $_.IdentityReference -like "$DuoServiceAccountName" }

	if (!$RegKeyPermissions) {
		$script:OutputValues.LogOutput += "Duo service account does not have permissions to relevant registry key."
		$script:OutputValues.Alert = 1
		$script:OutputValues.AccountPermission = 0
	} else {
		$RegKeyPermissionsCheck = $RegKeyPermissions | Where-Object { ($_.RegistryRights -eq "FullControl") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$RegKeyPermissionsCheck) {
			$script:OutputValues.LogOutput += "Duo service account does have permissions to relevant registry key but they are not sufficient. Please adjust."
			$script:OutputValues.Alert = 1
			$script:OutputValues.AccountPermission = 0
		} else {
			$script:OutputValues.LogOutput += "Duo service account has appropriate permissions to the relevant registry key."
		}
	}
	
	### Check log directory permissions
	$LogDirPermissions = (Get-Acl "$DuoConfigPath\log").Access | 
							Where-Object { $_.IdentityReference -like "$DuoServiceAccountName" }

	if (!$LogDirPermissions) {
		$script:OutputValues.LogOutput += "Duo service account does not have permissions to the log directory."
		$script:OutputValues.Alert = 1
		$script:OutputValues.AccountPermission = 0
	} else {
		$LogDirPermissionsCheck = $LogDirPermissions | Where-Object { ($_.FileSystemRights -eq "Modify, Synchronize") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$LogDirPermissionsCheck) {
			$script:OutputValues.LogOutput += "Duo service account does have permissions to the log directory but they are not sufficient. Please adjust."
			$script:OutputValues.Alert = 1
			$script:OutputValues.AccountPermission = 0
		} else {
			$script:OutputValues.LogOutput += "Duo service account has appropriate permissions to the log directory."
		}
	}
	
	### Check conf directory permissions
	$ConfDirPermissions = (Get-Acl "$DuoConfigPath\conf").Access | 
							Where-Object { $_.IdentityReference -like "$DuoServiceAccountName" }

	if (!$ConfDirPermissions) {
		$script:OutputValues.LogOutput += "Duo service account does not have permissions to the log directory."
		$script:OutputValues.Alert = 1
		$script:OutputValues.AccountPermission = 0
	} else {
		$ConfDirPermissionsCheck = $ConfDirPermissions | Where-Object { ($_.FileSystemRights -eq "ReadAndExecute, Synchronize") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$ConfDirPermissionsCheck) {
			$script:OutputValues.LogOutput += "Duo service account does have permissions to the conf directory but they are not sufficient. Please adjust."
			$script:OutputValues.Alert = 1
			$script:OutputValues.AccountPermission = 0
		} else {
			$script:OutputValues.LogOutput += "Duo service account has appropriate permissions to the conf directory."
		}
	}
	
	### Check ProgramData directory permissions
	$ProgramDataPermissions = (Get-Acl "C:\ProgramData\Duo Authentication Proxy").Access | 
							Where-Object { $_.IdentityReference -like "$DuoServiceAccountName" }

	if (!$ProgramDataPermissions) {
		$script:OutputValues.LogOutput += "Duo service account does not have permissions to the Duo directory in ProgramData."
		$script:OutputValues.Alert = 1
		$script:OutputValues.AccountPermission = 0
	} else {
		$ProgramDataPermissionsCheck = $ProgramDataPermissions | Where-Object { ($_.FileSystemRights -eq "Modify, Synchronize") -AND ($_.AccessControlType -eq "Allow") }
		
		if (!$ProgramDataPermissionsCheck) {
			$script:OutputValues.LogOutput += "Duo service account does have permissions to the Duo directory in ProgramData but they are not sufficient. Please adjust."
			$script:OutputValues.Alert = 1
			$script:OutputValues.AccountPermission = 0
		} else {
			$script:OutputValues.LogOutput += "Duo service account has appropriate permissions to the Duo directory in ProgramData."
		}
	}
}

function CheckLastMonthUse {
	$LastUse = Get-Content "$DuoConfigPath\log\authproxy.log" | ? { $_ -like "*Success. Logging you in...*" }
	if ($LastUse) {
		try {
			$LastUseDateString = $LastUse[-1].Substring(0,10)
			$LastUseDateTime= [datetime]::ParseExact($LastUseDateString, "yyyy-MM-dd", $null)
			if ($LastUseDateTime -ge (Get-Date).AddDays(-30)) {
				$script:OutputValues.LogOutput += "Successful login within last month."
				$script:OutputValues.SuccessLastMonth = 1
			} else {
				$script:OutputValues.LogOutput += "No successful logins within last month."
				$script:OutputValues.SuccessLastMonth = 0
			}
		} catch {
			$script:OutputValues.LogOutput += "Successful login found but could not parse date."
			$script:OutputValues.SuccessLastMonth = 0
		}
	} else {
		$script:OutputValues.LogOutput += "Could not find evidence of successful login in log."
		$script:OutputValues.SuccessLastMonth = 0
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
			   $script:OutputValues.Alert = 1
			   $script:OutputValues.ConnectivityTool = 0
				$script:OutputValues.LogOutput += "Duo Connectivity Tool found configuration errors"
				if ($ConnectivityValidationErrors -eq 1) {
					$script:OutputValues.LogOutput += "Duo Connectivity Tool reported that configuration validation was not successful."
				}
			} else {
				$script:OutputValues.LogOutput += "Duo Connectivity Tool reported no errors."
				$script:OutputValues.ConnectivityTool = 1
			}
		} else {
			$script:OutputValues.Alert = 1
			$script:OutputValues.ConnectivityTool = 0
			$script:OutputValues.LogOutput += "Duo Connectivity Tool produced no output."
		}
	} catch {
		$script:OutputValues.Alert = 1
		$script:OutputValues.ConnectivityTool = 0
		$script:OutputValues.LogOutput += "Error running Duo Connectivity Tool"
	}	
}


### Code logic

IsDuoRunning
CheckFailMode
CheckAllKeysProtected
CheckLDAPS
CheckSecurityGroup
CheckLogServiceUser
CheckServiceRunAsUser
CheckServiceAccountPermissions
CheckLastMonthUse
TestDuoConnectivityTool
$Final = [string]::Join("|",($OutputValues.GetEnumerator() | ForEach-Object { $_.Name + "=" + $_.Value }))
Write-Output $Final