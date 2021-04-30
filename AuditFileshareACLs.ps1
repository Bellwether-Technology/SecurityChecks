$shares = Get-SmbShare -Special $false -ErrorAction SilentlyContinue `
    | Where-Object {$_.Name -ne "SYSVOL" -and $_.Name -ne "NETLOGON" -and $_.Name -ne "print$" -and $_.ShareType -eq "FileSystemDirectory"} `
    | Where-Object {$_.Description -notlike "XFSRM*"}

$AllAclObjects = @()

$shares | ForEach-Object {
    $AclObject = ""
    $Path = $_.Path
    $Access = (Get-Acl -Path $Path).Access | Select-Object IdentityReference,FileSystemRights,IsInherited,AccessControlType,InheritanceFlags
    $Access | ForEach-Object {
        $AclProperties = @{
            Path = $Path
            Identity = $_.IdentityReference
            Permissions = $_.FileSystemRights
            IsInherited = $_.IsInherited
            AccessControlType = $_.AccessControlType
            InheritanceFlags = $_.InheritanceFlags
        }
        $AclObject = New-Object -TypeName PSObject -Property $AclProperties

        $AllAclObjects += $AclObject
    }
}

$Date = Get-Date -Format "yyyy-MM-dd"
$Hostname = hostname
$AllAclObjects | Select-Object Path,Identity,Permissions,AccessControlType,IsInherited,InheritanceFlags | 
                 ConvertTo-Csv | Out-File "C:\$Date-$Hostname-ACLAudit.csv"