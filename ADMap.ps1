Function Get-LdapPassword {
<#
.SYNOPSIS
    Get plaintext passwords from Active Directory.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-LdapPassword queries domain controller via LDAP protocol for accounts with common attributes containing passwords (UnixUserPassword, UserPassword, ms-MCS-AdmPwd, msDS-ManagedPassword and more).

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specify the domain account to use.

.PARAMETER Attributes
    Specify specific attributes to search through.

.PARAMETER Keywords
    Specify specific keywords to search for.

.EXAMPLE
    PS C:\> Get-LdapPassword -Server ADATUM.CORP -Credential ADATUM\testuser

.EXAMPLE
    PS C:\> Get-LdapPassword -Server ADATUM.CORP -Attributes description,comment -Keywords pw,mdp
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Attributes = @("description"),

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Keywords = @("cred", "pass", "pw")
    )

    $searchString = "LDAP://$Server/RootDSE"
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
    $rootDN = $rootDSE.rootDomainNamingContext[0]
    $adsPath = "LDAP://$Server/$rootDN"

    # Searching for password in world-readable attributes
    $filter = ''
    foreach ($attribute in $Attributes) {
        foreach ($keyword in $Keywords) {
            $filter += "($attribute=*$keyword*)"
        }
    }
    $filter = "(&(objectClass=user)(|$filter))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        foreach ($attribute in $attributes) {
            if ($_.$attribute) {
                [pscustomobject] @{
                    SamAccountName = $_.sAMAccountName
                    Attribute = $attribute
                    Value = $_.$attribute
                }
            }
        }
    }

    # Searching for encoded password attributes
    # Reference: https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/
    $filter = ''
    $attributes = @("UnixUserPassword", "UserPassword", "msSFU30Password", "unicodePwd")
    foreach ($attribute in $Attributes) {
        $filter += "($attribute=*)"
    }
    $filter = "(&(objectClass=user)(|$filter))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        foreach ($attribute in $attributes) {
            if ($_.$attribute) {
                [pscustomobject] @{
                    SamAccountName = $_.sAMAccountName
                    Attribute = $attribute
                    Value = [Text.Encoding]::ASCII.GetString($_.$attribute)
                }
            }
        }
    }

    # Searching for LAPS passwords
    # Reference: https://adsecurity.org/?p=1790
    $filter = "(&(objectCategory=Computer)(ms-MCS-AdmPwd=*))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        if ($_.'ms-MCS-AdmPwd') {
            [pscustomobject] @{
                SamAccountName = $_.sAMAccountName
                Attribute = 'ms-MCS-AdmPwd'
                Value = $_.'ms-MCS-AdmPwd'
            }
        }
    }

    # Searching for GMSA passwords
    # Reference: https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/
    $filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(msDS-ManagedPasswordId=*))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        if ($_.'msDS-ManagedPassword') {
            [pscustomobject] @{
                SamAccountName = $_.sAMAccountName
                Attribute = 'msDS-ManagedPassword'
                Value = ConvertTo-NTHash -Password (ConvertFrom-ADManagedPasswordBlob -Blob $_.'msDS-ManagedPassword').CurrentPassword
            }
        }
    }

    Function Local:ReadSecureWString {
        Param (
            [byte[]] $Buffer,
            [int] $StartIndex
        )
        $maxLength = $Buffer.Length - $StartIndex;
        $result = New-Object SecureString
        for ($i = $startIndex; $i -lt $buffer.Length; $i += [Text.UnicodeEncoding]::CharSize) {
            $c = [BitConverter]::ToChar($buffer, $i)
            if ($c -eq [Char]::MinValue) {
                return $result
            }
            $result.AppendChar($c)
        }
    }

    Function Local:ConvertFrom-ADManagedPasswordBlob {
        Param (
            [byte[]] $Blob
        )
        $stream = New-object IO.MemoryStream($Blob)
        $reader = New-Object IO.BinaryReader($stream)
        $version = $reader.ReadInt16()
        $reserved = $reader.ReadInt16()
        $length = $reader.ReadInt32()
        $currentPasswordOffset = $reader.ReadInt16()
        $secureCurrentPassword = ReadSecureWString -Buffer $blob -StartIndex $currentPasswordOffset
        $previousPasswordOffset = $reader.ReadInt16()
        [SecureString] $securePreviousPassword = $null
        if($previousPasswordOffset > 0) {
            $securePreviousPassword = ReadSecureWString -Buffer $blob -StartIndex $previousPasswordOffset
        }
        $queryPasswordIntervalOffset = $reader.ReadInt16()
        $queryPasswordIntervalBinary = [BitConverter]::ToInt64($blob, $queryPasswordIntervalOffset)
        $queryPasswordInterval = [TimeSpan]::FromTicks($queryPasswordIntervalBinary)
        $unchangedPasswordIntervalOffset = $reader.ReadInt16()
        $unchangedPasswordIntervalBinary = [BitConverter]::ToInt64($blob, $unchangedPasswordIntervalOffset)
        $unchangedPasswordInterval = [TimeSpan]::FromTicks($unchangedPasswordIntervalBinary)
        New-Object PSObject -Property @{
            CurrentPassword = $secureCurrentPassword.ToUnicodeString()
            PreviousPassword = $securePreviousPassword.ToUnicodeString()
            QueryPasswordInterval = $queryPasswordInterval
            UnchangedPasswordInterval = $unchangedPasswordInterval
        }
    }

    Function Local:ConvertTo-NTHash {
        Param (
            [string] $Password
        )
        $ntHash = New-Object byte[] 16
        $unicodePassword = New-Object Win32+UNICODE_STRING $Password
        [Win32]::RtlCalculateNtOwfPassword([ref] $unicodePassword, $ntHash) | Out-Null
        $unicodePassword.Dispose()
        return (($ntHash | ForEach-Object ToString X2) -join '')
    }
}

Function Get-PrivExchangeStatus {
<#
.SYNOPSIS
    Get PrivExchange exploitability regarding to Active Directory rights granted to the group 'Exchange Windows Permissions'.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-PrivExchangeStatus queries a domain controller via LDAP protocol for WriteDacl ACL granted for the group 'Exchange Windows Permissions'.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specify the domain account to use.

.EXAMPLE
    PS C:\> Get-PrivExchangeStatus -Server ADATUM.CORP -Credential ADATUM\testuser
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $searchString = "LDAP://$Server/RootDSE"
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
    $rootDN = $rootDSE.rootDomainNamingContext[0]
    $adsPath = "LDAP://$Server/$rootDN"

    $privExchangeAcl = $false
    $groupId = 'Exchange Windows Permissions'
    $objectSid = $(Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter "(samAccountName=$groupId)" -Properties objectsid).objectsid
    $groupSid = (New-Object Security.Principal.SecurityIdentifier($objectSid, 0)).Value
    Write-Verbose "SID of the group 'Exchange Windows Permissions': $groupSid"
    if ($groupSid -and (Get-LdapObjectAcl -ADSpath $adsPath -Credential $Credential -Filter "(DistinguishedName=$rootDN)" | ? { ($_.SecurityIdentifier -imatch "$groupSid") -and ($_.ActiveDirectoryRights -imatch 'WriteDacl') -and -not ($_.AceFlags -imatch 'InheritOnly') })) {
        $privExchangeAcl = $true
    }
    Write-Output $privExchangeAcl
}

Function Get-ExchangeVersion {
<#
.SYNOPSIS
    Enumerate Exchange servers from Active Directory and check for exploitable vulnerabilities.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-ExchangeVersion queries domain controller via LDAP protocol for Exchange information.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specify the domain account to use.

.EXAMPLE
    PS C:\> Get-ExchangeVersion -Server ADATUM.CORP -Credential ADATUM\testuser
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Function Local:ConvertTo-ExchangeVersion($Version) {
        $versionSizeInBits = 32
        $binaryVersion = [Convert]::ToString([int32]$Version,2)
        for ($i = $($binaryVersion.Length); $i -lt $versionSizeInBits; $i++){
            $binaryVersion = '0' + $binaryVersion
        }
        New-Object PSObject -Property @{
            LegacyVersionStructure = [Convert]::ToInt16($binaryVersion.Substring(0,4),2)
            MajorVersion = [Convert]::ToInt16($binaryVersion.Substring(4,6),2)
            MinorVersion = [Convert]::ToInt16($binaryVersion.Substring(10,6),2)
            Flag = [Convert]::ToInt16($binaryVersion.Substring(16,1),2)
            Build = [Convert]::ToInt16($binaryVersion.Substring(17,15),2)
        }
    }

    $searchString = "LDAP://$Server/RootDSE"
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
    $rootDN = $rootDSE.rootDomainNamingContext[0]
    $adsPath = "LDAP://$Server/$rootDN"

    $roleDictionary = @{2  = "MB"; 4  = "CAS"; 16 = "UM"; 32 = "HT"; 64 = "ET"}
    $properties = 'sAMAccountName', 'msExchCurrentServerRoles', 'networkAddress', 'versionNumber'
    $filter = "(|(objectClass=msExchExchangeServer)(objectClass=msExchClientAccessArray))"
    $configurationNamingContext = $rootDSE.configurationNamingContext[0]
    $exchangeServers = Get-LdapObject -ADSpath "LDAP://$Server/$configurationNamingContext" -Credential $Credential -Filter $filter -Properties $properties
    foreach ($exchServer in $exchangeServers) {
        $privExchange = $false
        $CVE20200688  = $false
        $proxyLogon = $false
        $exchVersion = ConvertTo-ExchangeVersion $exchServer.versionNumber
        switch ($exchVersion.MajorVersion) {
            "15" {
                switch ($exchVersion.MinorVersion) {
                    "0" {
                        if ([int]$exchVersion.Build -lt 1473) { $privExchange = $true }
                        if ([int]$exchVersion.Build -lt 1497) { $CVE20200688 = $true; $proxyLogon = $true }
                    }
                    "1" {
                        if ([int]$exchVersion.Build -lt 1713) { $privExchange = $true }
                        if ([int]$exchVersion.Build -lt 1847) { $CVE20200688 = $true }
                        if ([int]$exchVersion.Build -lt 2106) { $proxyLogon = $true }
                    }
                    "2" {
                        if ([int]$exchVersion.Build -lt 330) { $privExchange = $true }
                        if ([int]$exchVersion.Build -lt 464) { $CVE20200688 = $true }
                        if ([int]$exchVersion.Build -lt 721) { $proxyLogon = $true }
                    }
                }
            }
            "14" {
                switch ($exchVersion.MinorVersion) {
                    "3" {
                        if ([int]$exchVersion.Build -lt 442) { $privExchange = $true }
                        if ([int]$exchVersion.Build -lt 496) { $CVE20200688 = $true; $proxyLogon = $true }
                    }
                }
            }
        }
        $obj = [pscustomobject] @{
            Fqdn            = ($exchServer.networkAddress | Where-Object -FilterScript {$_ -like "ncacn_ip_tcp*"}).Split(":")[1]
            Roles           = [string] ($roleDictionary.Keys | ?{$_ -band $exchServer.msExchCurrentServerRoles} | %{$roleDictionary.Get_Item($_)})
            Version         = "$($exchVersion.MajorVersion).$($exchVersion.MinorVersion).$($exchVersion.Build)"
            PrivExchange    = $privExchange
            'CVE-2020-0688' = $CVE20200688
            ProxyLogon      = $proxyLogon
        }
        Write-Output $obj
    }
}

Function Get-LegacyComputer {
<#
.SYNOPSIS
    Enumerate legacy Windows computers.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-LegacyComputer queries domain controller via LDAP protocol for outdated operating systems.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specify the domain account to use.

.EXAMPLE
    PS C:\> Get-LegacyComputer -Server ADATUM.CORP -Credential ADATUM\testuser
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $searchString = "LDAP://$Server/RootDSE"
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
    $rootDN = $rootDSE.rootDomainNamingContext[0]
    $adsPath = "LDAP://$Server/$rootDN"

    $legacyOS = '2000', '2003', '2008', 'ME', 'XP', 'Vista', 'Windows NT', 'Windows 7', 'Windows 8'
    $filter = ''
    foreach($os in $legacyOS) {
        $filter += "(operatingsystem=*$os*)"
    }
    $filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2)(|$filter))"
    $properties = 'dnsHostname', 'samAccountName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack', 'LastLogon'
    Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
        Write-Output (
            [pscustomobject] @{
                sAMAccountName = $_.samAccountName
                ComputerName = $_.dnsHostname
                OperatingSystem = $_.operatingSystem
                Version = $_.operatingSystemVersion
                ServicePack = $_.operatingSystemServicePack
                LastLogon = ([datetime]::FromFileTime(($_.LastLogon)))
            }
        )
    }
}

Function Local:Get-LdapObject {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ADSpath,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
        $Filter = '(objectClass=*)',

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($Credential.UserName) {
        $domainObject = New-Object DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
    }
    $searcher.SearchScope = $SearchScope
    $searcher.PageSize = $PageSize
    $searcher.CacheResults = $false
    $searcher.filter = $Filter
    $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
    $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
    try {
        $results = $searcher.FindAll()
        $results | Where-Object {$_} | ForEach-Object {
            $objectProperties = @{}
            $p = $_.Properties
            $p.PropertyNames | ForEach-Object {
                if (($_ -ne 'adspath') -And ($p[$_].count -eq 1)) {
                    $objectProperties[$_] = $p[$_][0]
                }
                elseif ($_ -ne 'adspath') {
                    $objectProperties[$_] = $p[$_]
                }
            }
            New-Object -TypeName PSObject -Property ($objectProperties)
        }
        $results.dispose()
        $searcher.dispose()
    }
    catch {
        Write-Error $_ -ErrorAction Stop
    }
}

Function Local:Get-LdapObjectAcl {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ADSpath,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
        $Filter = '(objectClass=domain)',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($Credential.UserName) {
        $domainObject = New-Object DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
    }
    $searcher.SearchScope = $SearchScope
    $searcher.PageSize = $PageSize
    $searcher.CacheResults = $false
    $searcher.filter = $Filter
    $propertiesToLoad = 'objectsid', 'ntsecuritydescriptor', 'distinguishedname'
    $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
    $searcher.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
    try {
        $results = $searcher.FindAll()
        $results | Where-Object {$_} | ForEach-Object {
            $p = $_.Properties
            $objectSid = $null
            if ($p.objectsid -and $p.objectsid[0]) {
                $objectSid = (New-Object Security.Principal.SecurityIdentifier($p.objectsid[0], 0)).Value
            }
            New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $p['ntsecuritydescriptor'][0], 0 | ForEach-Object { $_.DiscretionaryAcl } | ForEach-Object {
                $_ | Add-Member NoteProperty 'ObjectDN' $p.distinguishedname[0]
                $_ | Add-Member NoteProperty 'ObjectSID' $objectSid
                $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                Write-Output $_
            }
        }
        $results.dispose()
        $searcher.dispose()
    }
    catch {
        Write-Error $_ -ErrorAction Stop
    }
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "SystemFunction007", CharSet = CharSet.Unicode)]
    public static extern int RtlCalculateNtOwfPassword(ref UNICODE_STRING password, [MarshalAs(UnmanagedType.LPArray)] byte[] hash);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;

        public UNICODE_STRING(string s) {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose() {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }
    }
}
"@
