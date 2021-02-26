### Declare variables

$DuoServiceAccountName = "@DuoServiceAccountName@"

$DuoVersion = "@DuoVersion@"
$DuoVersionSplit = ($DuoVersion.Split('.'))[0]
if ([System.Int32]::Parse($DuoVersionSplit) -ge 5) {
    $DuoConfigPath = "C:\Program Files\Duo Security Authentication Proxy\"
} else {
    $DuoConfigPath = "C:\Program Files (x86)\Duo Security Authentication Proxy\"
}

$ProgramDataPath = "C:\ProgramData\Duo Authentication Proxy"
$RegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\DuoAuthProxy"


### Functions

function SetRegKeyAcl {
    try {
        ### Set registry ACL
        $ACL = Get-Acl -Path $RegKeyPath
        $RegKeyAccessRule = New-Object System.Security.AccessControl.RegistryAccessRule ($DuoServiceAccountName,"FullControl","ContainerInherit","None","Allow")
        $ACL.SetAccessRule($RegKeyAccessRule)
        $ACL | Set-Acl -Path $RegKeyPath
        Write-Output "Registry ACL has been set."
    } catch {
        Write-Output "Error setting registry key ACL."
    }
}

function SetLogDirAcl {
    try {
        ### Set log directory ACL
        $ACL = Get-Acl -Path "$DuoConfigPath\log"
        $LogDirAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DuoServiceAccountName,"Modify","ContainerInherit,ObjectInherit","None","Allow")
        $ACL.SetAccessRule($LogDirAccessRule)
        $ACL | Set-Acl -Path "$DuoConfigPath\log"
        Write-Output "Log directory ACL has been set."
    } catch {
        Write-Output "Error setting log directory ACL."
    }
}
function SetConfDirAcl {
    try {
        ### Set conf directory ACL
        $ACL = Get-Acl -Path "$DuoConfigPath\conf"
        $ConfDirAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DuoServiceAccountName,"ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")
        $ACL.SetAccessRule($ConfDirAccessRule)
        $ACL | Set-Acl -Path "$DuoConfigPath\conf"
        Write-Output "Conf directory ACL has been set."
    } catch {
        Write-Output "Error setting conf directory ACL."
    }
}

function SetProgramDataAcl {
    try {
        ### Set ProgramData Duo directory ACL
        $ACL = Get-Acl -Path $ProgramDataPath
        $ProgramDataAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DuoServiceAccountName,"Modify","ContainerInherit,ObjectInherit","None","Allow")
        $ACL.SetAccessRule($ProgramDataAccessRule)
        $ACL | Set-Acl -Path $ProgramDataPath
        Write-Output "Duo ProgramData directory ACL has been set."
    } catch {
        Write-Output "Error setting Duo ProgramData ACL."
    }
}


### Code logic

SetRegKeyAcl
SetLogDirAcl
SetConfDirAcl
SetProgramDataAcl