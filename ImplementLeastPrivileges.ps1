### Declare variables

$DuoServiceAccountName = '@DuoServiceAccountName@'
$DuoServiceAccountPassword = '@DuoServiceAccountPassword@'

$DuoVersion = "@DuoVersion@"
$DuoVersionSplit = ($DuoVersion.Split('.'))[0]
if ([System.Int32]::Parse($DuoVersionSplit) -ge 5) {
    $DuoConfigPath = "C:\Program Files\Duo Security Authentication Proxy\"
} else {
    $DuoConfigPath = "C:\Program Files (x86)\Duo Security Authentication Proxy\"
}

$ProgramDataPath = "C:\ProgramData\Duo Authentication Proxy"
$RegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\DuoAuthProxy"
$Alert = 0


### Class

$class=@"
using System.Text;
using System;
using System.Runtime.InteropServices;

public static class LsaWrapper 
{
// Import the LSA functions
 
[DllImport("advapi32.dll", PreserveSig = true)]
private static extern UInt32 LsaOpenPolicy(
    ref LSA_UNICODE_STRING SystemName,
    ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
    Int32 DesiredAccess,
    out IntPtr PolicyHandle
    );
 
[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
private static extern long LsaAddAccountRights(
    IntPtr PolicyHandle,
    IntPtr AccountSid,
    LSA_UNICODE_STRING[] UserRights,
    long CountOfRights);
 
[DllImport("advapi32")]
public static extern void FreeSid(IntPtr pSid);
 
[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, PreserveSig = true)]
private static extern bool LookupAccountName(
    string lpSystemName, string lpAccountName,
    IntPtr psid,
    ref int cbsid,
    StringBuilder domainName, ref int cbdomainLength, ref int use);
 
[DllImport("advapi32.dll")]
private static extern bool IsValidSid(IntPtr pSid);
 
[DllImport("advapi32.dll")]
private static extern long LsaClose(IntPtr ObjectHandle);
 
[DllImport("kernel32.dll")]
private static extern int GetLastError();
 
[DllImport("advapi32.dll")]
private static extern long LsaNtStatusToWinError(long status);
 
// define the structures
 
private enum LSA_AccessPolicy : long
{
    POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
    POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
    POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
    POLICY_TRUST_ADMIN = 0x00000008L,
    POLICY_CREATE_ACCOUNT = 0x00000010L,
    POLICY_CREATE_SECRET = 0x00000020L,
    POLICY_CREATE_PRIVILEGE = 0x00000040L,
    POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
    POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
    POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
    POLICY_SERVER_ADMIN = 0x00000400L,
    POLICY_LOOKUP_NAMES = 0x00000800L,
    POLICY_NOTIFICATION = 0x00001000L
}
 
[StructLayout(LayoutKind.Sequential)]
private struct LSA_OBJECT_ATTRIBUTES
{
    public int Length;
    public IntPtr RootDirectory;
    public readonly LSA_UNICODE_STRING ObjectName;
    public UInt32 Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}
 
[StructLayout(LayoutKind.Sequential)]
private struct LSA_UNICODE_STRING
{
    public UInt16 Length;
    public UInt16 MaximumLength;
    public IntPtr Buffer;
}
/// 
//Adds a privilege to an account
 
/// Name of an account - "domain\account" or only "account"
/// Name ofthe privilege
/// The windows error code returned by LsaAddAccountRights
public static long SetRight(String accountName, String privilegeName)
{
    long winErrorCode = 0; //contains the last error
 
    //pointer an size for the SID
    IntPtr sid = IntPtr.Zero;
    int sidSize = 0;
    //StringBuilder and size for the domain name
    var domainName = new StringBuilder();
    int nameSize = 0;
    //account-type variable for lookup
    int accountType = 0;
 
    //get required buffer size
    LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);
 
    //allocate buffers
    domainName = new StringBuilder(nameSize);
    sid = Marshal.AllocHGlobal(sidSize);
 
    //lookup the SID for the account
    bool result = LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize,
                                    ref accountType);
 
    if (!result)
    {
        winErrorCode = GetLastError();
        Console.WriteLine("LookupAccountName failed: " + winErrorCode);
        //return winErrorCode;
    }
    else
    {
        //initialize an empty unicode-string
        var systemName = new LSA_UNICODE_STRING();
        //combine all policies
        var access = (int) (
                                LSA_AccessPolicy.POLICY_AUDIT_LOG_ADMIN |
                                LSA_AccessPolicy.POLICY_CREATE_ACCOUNT |
                                LSA_AccessPolicy.POLICY_CREATE_PRIVILEGE |
                                LSA_AccessPolicy.POLICY_CREATE_SECRET |
                                LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION |
                                LSA_AccessPolicy.POLICY_LOOKUP_NAMES |
                                LSA_AccessPolicy.POLICY_NOTIFICATION |
                                LSA_AccessPolicy.POLICY_SERVER_ADMIN |
                                LSA_AccessPolicy.POLICY_SET_AUDIT_REQUIREMENTS |
                                LSA_AccessPolicy.POLICY_SET_DEFAULT_QUOTA_LIMITS |
                                LSA_AccessPolicy.POLICY_TRUST_ADMIN |
                                LSA_AccessPolicy.POLICY_VIEW_AUDIT_INFORMATION |
                                LSA_AccessPolicy.POLICY_VIEW_LOCAL_INFORMATION
                            );
        //initialize a pointer for the policy handle
        IntPtr policyHandle = IntPtr.Zero;
 
        //these attributes are not used, but LsaOpenPolicy wants them to exists
        var ObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
        ObjectAttributes.Length = 0;
        ObjectAttributes.RootDirectory = IntPtr.Zero;
        ObjectAttributes.Attributes = 0;
        ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
        ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;
 
        //get a policy handle
        uint resultPolicy = LsaOpenPolicy(ref systemName, ref ObjectAttributes, access, out policyHandle);
        winErrorCode = LsaNtStatusToWinError(resultPolicy);
 
        if (winErrorCode != 0)
        {
            Console.WriteLine("OpenPolicy failed: " + winErrorCode);
            //return winErrorCode;
        }
        else
        {
            //Now that we have the SID an the policy,
            //we can add rights to the account.
 
            //initialize an unicode-string for the privilege name
            var userRights = new LSA_UNICODE_STRING[1];
            userRights[0] = new LSA_UNICODE_STRING();
            userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
            userRights[0].Length = (UInt16) (privilegeName.Length*UnicodeEncoding.CharSize);
            userRights[0].MaximumLength = (UInt16) ((privilegeName.Length + 1)*UnicodeEncoding.CharSize);
 
            //add the right to the account
            long res = LsaAddAccountRights(policyHandle, sid, userRights, 1);
            winErrorCode = LsaNtStatusToWinError(res);
            if (winErrorCode != 0)
            {
                Console.WriteLine("LsaAddAccountRights failed: " + winErrorCode);
                //return winErrorCode;
            }
 
            LsaClose(policyHandle);
        }
        FreeSid(sid);
    }
 
    return winErrorCode;
}

}
"@


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
        $script:Alert = 1
    }
}

function SetLogDirAcl {
    try {
        ### Set log directory ACL
        $ACL = Get-Acl -Path "$DuoConfigPath\log"
        $LogDirAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DuoServiceAccountName,"Modify","ContainerInherit,ObjectInherit","None","Allow")
        $ACL.SetAccessRule($LogDirAccessRule)
        (Get-Item "$DuoConfigPath\log").SetAccessControl($ACL)
        Write-Output "Log directory ACL has been set."
    } catch {
        Write-Output "Error setting log directory ACL."
        $script:Alert = 1
    }
}

function SetConfDirAcl {
    try {
        ### Set conf directory ACL
        $ACL = Get-Acl -Path "$DuoConfigPath\conf"
        $ConfDirAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DuoServiceAccountName,"ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")
        $ACL.SetAccessRule($ConfDirAccessRule)
        (Get-Item "$DuoConfigPath\conf").SetAccessControl($ACL)
        Write-Output "Conf directory ACL has been set."
    } catch {
        Write-Output "Error setting conf directory ACL."
        $script:Alert = 1
    }
}

function SetProgramDataAcl {
    try {
        ### Set ProgramData Duo directory ACL
        $ACL = Get-Acl -Path $ProgramDataPath
        $ProgramDataAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DuoServiceAccountName,"Modify","ContainerInherit,ObjectInherit","None","Allow")
        $ACL.SetAccessRule($ProgramDataAccessRule)
        (Get-Item $ProgramDataPath).SetAccessControl($ACL)
        Write-Output "Duo ProgramData directory ACL has been set."
    } catch {
        Write-Output "Error setting Duo ProgramData ACL."
        $script:Alert = 1
    }
}

function SetServiceLogonUser {
    if ($script:Alert -eq 0) {        
        Add-Type -TypeDefinition $class
        [lsawrapper]::SetRight("$DuoServiceAccountName","SeServiceLogonRight")
        $ServiceObject  = Get-CimInstance win32_service -filter "name='DuoAuthProxy'"
        
        $ServiceObject | Invoke-CimMethod -Name StopService | Out-Null
        $ServiceObject | Invoke-CimMethod -Name Change -Arguments @{StartName="$DuoServiceAccountName"}
        $ServiceObject | Invoke-CimMethod -Name Change -Arguments @{StartPassword="$DuoServiceAccountPassword"}
        $ServiceObject | Invoke-CimMethod -Name StartService | Out-Null
    } else {
        Write-Output "Error(s) occurred while setting permissions. Please fix these before setting service user."
    }
}


### Code logic
Get-Service DuoAuthProxy | Start-Service
SetRegKeyAcl
SetLogDirAcl
SetConfDirAcl
SetProgramDataAcl
SetServiceLogonUser