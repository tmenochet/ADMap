Function Get-DomainInfo {
<#
.SYNOPSIS
    Get basic information about a given Active Directory domain.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-DomainInfo queries domain controller via LDAP protocol for basic information concerning Active Directory configuration.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the domain account to use.

.EXAMPLE
    PS C:\> Get-DomainInfo -Server ADATUM.CORP -Credential ADATUM\testuser
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

    BEGIN {
        $functionalLevels = @{
            0 = 'Windows 2000'
            1 = 'Windows Server 2003 Interim'
            2 = 'Windows Server 2003'
            3 = 'Windows Server 2008'
            4 = 'Windows Server 2008 R2'
            5 = 'Windows Server 2012'
            6 = 'Windows Server 2012 R2'
            7 = 'Windows Server 2016'
        }

        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $configurationNC = $rootDSE.configurationNamingContext[0]
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $filter = '(objectClass=domain)'
        $properties = 'name','objectsid','ms-ds-machineaccountquota'
        $domain = Get-LdapObject -ADSpath "LDAP://$Server/$defaultNC" -Credential $Credential -Filter $filter -Properties $properties -SearchScope 'Base'

        $filter = '(objectClass=site)'
        $sites = (Get-LdapObject -ADSpath "LDAP://$Server/$configurationNC" -Credential $Credential -Filter $filter -Properties 'name').name

        $filter = '(&(objectCategory=nTDSDSA)(options:1.2.840.113556.1.4.803:=1))'
        $globalCatalogs = (Get-LdapObject -ADSpath "LDAP://$Server/$configurationNC" -Credential $Credential -Filter $filter -Properties 'distinguishedname').distinguishedname
        $globalCatalogs = $globalCatalogs -replace 'CN=NTDS Settings,'

        Write-Output ([pscustomobject] @{
            DomainName                      = $defaultNC -replace 'DC=' -replace ',','.'
            NetbiosName                     = $domain.name
            DomainSID                       = (New-Object Security.Principal.SecurityIdentifier($domain.objectsid, 0)).Value
            Forest                          = ($rootDSE.rootDomainNamingContext[0]) -replace 'DC=' -replace ',','.'
            ForestFunctionalLevel           = $functionalLevels[[int] $rootDSE.forestFunctionality[0]]
            DomainFunctionalLevel           = $functionalLevels[[int] $rootDSE.domainFunctionality[0]]
            DomainControllerFunctionalLevel = $functionalLevels[[int] $rootDSE.domainControllerFunctionality[0]]
            GlobalCatalogs                  = $globalCatalogs
            Sites                           = $sites
            MachineAccountQuota             = $domain.'ms-ds-machineaccountquota'
        })
    }
}

Function Get-TrustRelationship {
<#
.SYNOPSIS
    Enumerate trust relationships defined in an Active Directory domain.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-TrustRelationship queries domain controller via LDAP protocol for domain trusts.
    It is a slightly modified version of PowerView's Get-DomainTrust by @harmj0y.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the domain account to use.

.EXAMPLE
    PS C:\> Get-TrustRelationship -Server ADATUM.CORP -Credential ADATUM\testuser
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

    BEGIN {
        Function Get-SidFilteringStatus {
            Param (
                [int] $TrustDirection,
                [uint32] $TrustAttributes
            )

            if ($TrustDirection -eq 0 -or $TrustDirection -eq 1 -or ($TrustAttributes -band 32) -or ($TrustAttributes -band 0x400) -or ($TrustAttributes -band 0x00400000) -or ($trustAttributes -band 0x00800000)) {
                return "N/A"
            }
            if ($TrustAttributes -band 8) {
                if ($TrustAttributes -band 4) {
                    # quarantined
                    return "Yes"
                }
                elseif ($TrustAttributes -band 64) {
                    # forest trust migration
                    return "No"
                }
                return "Yes"
            }
            elseif ($TrustAttributes -band 0x00800000) {
                # obsolete tree root which
                return "N/A"
            }
            else {
                if ($TrustAttributes -band 4) {
                    # quarantined
                    return "Yes"
                }
                return "No"
            }
        }

       $trustAttributes = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }

        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/CN=System,$defaultNC"
            $domain = $defaultNC -replace 'DC=' -replace ',','.'
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $filter = '(objectCategory=trustedDomain)'
        $properties = 'distinguishedName','trustPartner','securityIdentifier','trustDirection','trustType','trustAttributes','whenCreated','whenChanged'
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
            $obj = $_
            $trustType = Switch ($obj.trustType) {
                1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                3 { 'MIT' }
            }
            $trustDirection = Switch ($obj.trustDirection) {
                0 { 'Disabled' }
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
            }
            $trustAttrib = @()
            $trustAttrib += $trustAttributes.Keys | Where-Object { $obj.trustAttributes -band $_ } | ForEach-Object { $trustAttributes[$_] }
            $sidFiltering = Get-SidFilteringStatus -TrustDirection $obj.trustDirection -TrustAttributes $obj.trustAttributes

            Write-Output ([pscustomobject] @{
                TrusteeDomainName   = $domain
                TrustedDomainName   = $obj.trustPartner
                TrustedDomainSID    = (New-Object Security.Principal.SecurityIdentifier($obj.securityIdentifier,0)).Value
                TrustType           = $trustType
                TrustDirection      = $trustDirection
                SidFiltering        = $sidFiltering
                TrustAttribute      = $trustAttrib
                WhenCreated         = $obj.whenCreated
                WhenChanged         = $obj.whenChanged
            })
        }
    }
}

Function Get-PasswordPolicy {
<#
.SYNOPSIS
    Get password policies defined in an Active Directory domain.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-LdapPassword queries domain controller via LDAP protocol for default password policy as well as fine-grained password policies.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the domain account to use.

.EXAMPLE
    PS C:\> Get-PasswordPolicy -Server ADATUM.CORP -Credential ADATUM\testuser
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

    BEGIN {
        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        # Enumerate domain password policy
        $filter = '(objectClass=domain)'
        $properties = 'distinguishedName','displayname','name','minPwdLength','minPwdAge','maxPwdAge','pwdHistoryLength','pwdProperties','lockoutDuration','lockoutThreshold','lockoutObservationWindow'
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties -SearchScope 'Base' | ForEach-Object {
            $complexityEnabled = $false
            if ($_.pwdProperties -band 1) {
                $complexityEnabled = $true
            }
            $reversibleEncryptionEnabled = $false
            if ($_.pwdProperties -band 16) {
                $reversibleEncryptionEnabled = $true
            }
            Write-Output ([pscustomobject] @{
                DisplayName = 'Default Domain Policy'
                DistinguishedName = $_.distinguishedName
                AppliesTo = $_.name
                MinPasswordLength = $_.minPwdLength
                MinPasswordAge = [TimeSpan]::FromTicks([Math]::ABS($_.minPwdAge)).ToString()
                MaxPasswordAge = [TimeSpan]::FromTicks([Math]::ABS($_.maxPwdAge)).ToString()
                PasswordHistoryCount = $_.pwdHistoryLength
                ComplexityEnabled = $complexityEnabled
                ReversibleEncryptionEnabled = $reversibleEncryptionEnabled
                LockoutThreshold = $_.lockoutThreshold
                LockoutDuration = [TimeSpan]::FromTicks([Math]::ABS($_.lockoutDuration)).ToString()
                LockoutObservationWindow = [TimeSpan]::FromTicks([Math]::ABS($_.lockoutObservationWindow)).ToString()
            })
        }

        # Enumerate fine-grained password policies
        $filter = '(objectClass=msDS-PasswordSettings)'
        $properties = 'distinguishedName','displayname','msds-lockoutthreshold','msds-psoappliesto','msds-minimumpasswordlength','msds-passwordhistorylength','msds-lockoutobservationwindow','msds-lockoutduration','msds-minimumpasswordage','msds-maximumpasswordage','msds-passwordsettingsprecedence','msds-passwordcomplexityenabled','msds-passwordreversibleencryptionenabled'
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
            Write-Output ([pscustomobject] @{
                DisplayName = $_.displayname
                DistinguishedName = $_.distinguishedName
                AppliesTo = $_.'msds-psoappliesto'
                MinPasswordLength = $_.'msds-minimumpasswordlength'
                MinPasswordAge = [TimeSpan]::FromTicks([Math]::ABS($_.'msds-minimumpasswordage')).ToString()
                MaxPasswordAge = [TimeSpan]::FromTicks([Math]::ABS($_.'msds-maximumpasswordage')).ToString()
                PasswordHistoryCount = $_.'msds-passwordhistorylength'
                ComplexityEnabled = $_.'msds-passwordcomplexityenabled'
                ReversibleEncryptionEnabled = $_.'msds-passwordreversibleencryptionenabled'
                LockoutThreshold = $_.'msds-lockoutthreshold'
                LockoutDuration = [TimeSpan]::FromTicks([Math]::ABS($_.'msds-lockoutduration')).ToString()
                LockoutObservationWindow = [TimeSpan]::FromTicks([Math]::ABS($_.'msds-lockoutobservationwindow')).ToString()
            })
        }
    }
}

Function Get-PotentiallyVoidPassword {
<#
.SYNOPSIS
    Get user accounts allowed to have void password.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-PotentiallyVoidPassword queries domain controller via LDAP protocol for enabled user accounts configured with the flag UF_DONT_EXPIRE_PASSWD.
    For each account, information about other UAC flags related to password is also retrieved.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the domain account to use.

.EXAMPLE
    PS C:\> Get-PotentiallyVoidPassword -Server ADATUM.CORP -Credential ADATUM\testuser
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

    BEGIN {
        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $properties = 'sAMAccountName','whenCreated','pwdLastSet','userAccountControl'
        $filter = "(&(!userAccountControl:1.2.840.113556.1.4.803:=2)(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))"
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
            [int32] $userAccountControl = $_.userAccountControl

            $isPasswordExpires = $true
            if ($userAccountControl -band 65536) {
                # DONT_EXPIRE_PASSWD
                $isPasswordExpires = $false
            }

            $isPasswordExpired = $false
            if ($userAccountControl -band 8388608) {
                # PASSWORD_EXPIRED
                $isPasswordExpired = $true
            }

            $preauthNotRequired = $false
            if ($userAccountControl -band 4194304) {
                # DONT_REQ_PREAUTH
                $preauthNotRequired = $true
            }

            Write-Output ([pscustomobject] @{
                sAMAccountName          = $_.sAMAccountName
                PasswordNotRequired     = $true
                WhenCreated             = $_.whenCreated
                PasswordLastSet         = [datetime]::FromFileTime($_.pwdLastSet)
                IsPasswordExpires       = $isPasswordExpires
                IsPasswordExpired       = $isPasswordExpired
                IsPreauthRequired       = (-not $preauthNotRequired)
            })
        }
    }
}

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
    Specifies the domain account to use.

.PARAMETER Attributes
    Specifies specific attributes to search through.

.PARAMETER Keywords
    Specifies specific keywords to search for.

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

        [String[]]
        $Attributes = @("description"),

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Keywords = @("cred", "pass", "pw")
    )

    BEGIN {
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
            if ($previousPasswordOffset > 0) {
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

        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
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
                    Write-Output ([pscustomobject] @{
                        SamAccountName = $_.sAMAccountName
                        Attribute = $attribute
                        Value = $_.$attribute
                    })
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
                    Write-Output ([pscustomobject] @{
                        SamAccountName = $_.sAMAccountName
                        Attribute = $attribute
                        Value = [Text.Encoding]::ASCII.GetString($_.$attribute)
                    })
                }
            }
        }

        # Searching for LAPS passwords
        # Reference: https://adsecurity.org/?p=1790
        $filter = "(&(objectCategory=Computer)(ms-MCS-AdmPwd=*))"
        Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
            if ($_.'ms-MCS-AdmPwd') {
                Write-Output ([pscustomobject] @{
                    SamAccountName = $_.sAMAccountName
                    Attribute = 'ms-MCS-AdmPwd'
                    Value = $_.'ms-MCS-AdmPwd'
                })
            }
        }

        # Searching for GMSA passwords
        # Reference: https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/
        $filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(msDS-ManagedPasswordId=*))"
        Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
            if ($_.'msDS-ManagedPassword') {
                Write-Output ([pscustomobject] @{
                    SamAccountName = $_.sAMAccountName
                    Attribute = 'msDS-ManagedPassword'
                    Value = ConvertTo-NTHash -Password (ConvertFrom-ADManagedPasswordBlob -Blob $_.'msDS-ManagedPassword').CurrentPassword
                })
            }
        }
    }
}

Function Get-KerberoastableUser {
<#
.SYNOPSIS
    Get user accounts vulnerable to Kerberoast and ASREPRoast attacks.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-KerberoastableUser queries domain controller via LDAP protocol for enabled user accounts configured with a SPN attribute or the flag UF_DONT_REQ_PREAUTH.
    For each account, information about password expiration, encryption type supported and granted privileges is also retrieved.
    It is a slightly modified version of RiskySPN's Find-PotentiallyCrackableAccounts by @machosec.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the domain account to use.

.EXAMPLE
    PS C:\> Get-KerberoastableUser -Server ADATUM.CORP -Credential ADATUM\testuser
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

    BEGIN {
        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }

        $currentDate = Get-Date
    }

    PROCESS {
        $properties = 'sAMAccountName','servicePrincipalName','msDS-UserPasswordExpiryTimeComputed','pwdLastSet','msDS-SupportedEncryptionTypes','userAccountControl','msDS-AllowedToDelegateTo','memberOf'
        $filter = "(&(!userAccountControl:1.2.840.113556.1.4.803:=2)(samAccountType=805306368)(|(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304))(!(samAccountName=krbtgt)))"
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
            [int32] $userAccountControl = $_.userAccountControl

            # Kerberos preauthentication
            $preauthNotRequired = $false
            if ($userAccountControl -band 4194304) {
                # DONT_REQ_PREAUTH
                $preauthNotRequired = $true
            }

            # Password policy
            $crackingWindow = "N/A"
            if ($_.'msds-UserPasswordExpiryTimeComputed' -ne 9223372036854775807) {
                $passwordExpiryDate = [datetime]::FromFileTime($_.'msds-UserPasswordExpiryTimeComputed')
                $crackingWindow = $passwordExpiryDate.Subtract($currentDate).Days
            }
            $passwordLastSet = [datetime]::FromFileTime($_.pwdLastSet)
            $passwordAge = $currentDate.Subtract($passwordLastSet).Days
            $isPasswordExpires = $true
            if ($userAccountControl -band 65536) {
                # DONT_EXPIRE_PASSWD
                $isPasswordExpires = $false
                $crackingWindow = "Indefinitely"
            }

            # Encryption type
            $encType = "RC4-HMAC"
            [int32] $eType = $_.'msds-supportedencryptiontypes'
            if ($eType) {
                if ($eType -band 16) {
                    $encType = "AES256-HMAC"
                }
                elseif ($eType -band 8) {
                    $encType = "AES128-HMAC"
                }
            }
            else {
                if ($userAccountControl -band 2097152) {
                    # USE_DES_KEY_ONLY
                    $encType = "DES"
                }
            }

            # Kerberos delegation
            $kerberosDelegation = $false
            $delegationTargetService = 'None'
            if ($_.userAccountControl -band 524288) {
                # TRUSTED_FOR_DELEGATION
                $kerberosDelegation = 'Unconstrained'
                $delegationTargetService = 'Any'
            }
            elseif ($_.'msDS-AllowedToDelegateTo') {
                $kerberosDelegation = 'Constrained' 
                if ($userAccountControl -band 16777216) {
                    # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                    $kerberosDelegation = 'Protocol Transition'
                }
                $delegationTargetService = $_.'msDS-AllowedToDelegateTo'
            }

            Write-Output ([pscustomobject] @{
                sAMAccountName          = $_.sAMAccountName
                ServicePrincipalName    = $_.servicePrincipalName
                IsPreauthRequired       = (-not $preauthNotRequired)
                EncryptionType          = $encType
                PasswordAge             = $passwordAge
                IsPasswordExpires       = $isPasswordExpires
                CrackingWindow          = $crackingWindow
                MemberOf                = $_.memberOf -replace "CN=" -replace ",.*"
                KerberosDelegation      = $kerberosDelegation
                DelegationTargetService = $delegationTargetService
            })
        }
    }
}

Function Get-KerberosDelegation {
<#
.SYNOPSIS
    Enumerate Kerberos delegations.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-KerberosDelegation queries domain controller via LDAP protocol for enabled accounts granted with Kerberos delegation.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the domain account to use.

.EXAMPLE
    PS C:\> Get-KerberosDelegation -Server ADATUM.CORP -Credential ADATUM\testuser
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

    BEGIN {
        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $filter = '(&(!userAccountControl:1.2.840.113556.1.4.803:=2)(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))'
        $properties = 'distinguishedName','sAMAccountName','objectClass','userAccountControl','msDS-AllowedToActOnBehalfOfOtherIdentity','lastLogon','servicePrincipalName','operatingSystem','operatingSystemVersion','operatingSystemServicePack'
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
            $obj = $_
            $kerberosDelegation = $false
            $delegationTargetService = 'None'
            $rbcdService = 'None'

            # Unconstrained delegation
            if ($_.userAccountControl -band 524288) {
                # TRUSTED_FOR_DELEGATION
                $kerberosDelegation = 'Unconstrained'
                $delegationTargetService = 'Any'
            }

            # Constrained delegation
            elseif ($_.'msDS-AllowedToDelegateTo') {
                $kerberosDelegation = 'Constrained'
                if ($userAccountControl -band 16777216) {
                    # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                    $kerberosDelegation = 'Protocol Transition'
                }
                $delegationTargetService = $_.'msDS-AllowedToDelegateTo'
            }

            if ($kerberosDelegation) {
                Write-Output ([pscustomobject] @{
                    sAMAccountName          = $_.samAccountName
                    DistinguishedName       = $_.distinguishedname
                    ObjectClass             = $_.objectClass
                    ServicePrincipalName    = $_.servicePrincipalName
                    KerberosDelegation      = $kerberosDelegation
                    DelegationTargetService = $delegationTargetService
                    LastLogon               = ([datetime]::FromFileTime(($_.LastLogon)))
                    OperatingSystem         = $_.operatingSystem
                    Version                 = $_.operatingSystemVersion
                    ServicePack             = $_.operatingSystemServicePack
                })
            }

            # Resource-based constrained delegation
            if ($rbcd = $obj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                $d = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $rbcd, 0
                $d.DiscretionaryAcl | ForEach-Object {
                    $filter = "(objectsid=$($_.SecurityIdentifier))"
                    Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
                        Write-Output ([pscustomobject] @{
                            sAMAccountName          = $_.samAccountName
                            DistinguishedName       = $_.distinguishedname
                            ObjectClass             = $_.objectClass
                            ServicePrincipalName    = $_.servicePrincipalName
                            KerberosDelegation      = 'Resource-Based Constrained'
                            DelegationTargetService = $obj.distinguishedname
                            LastLogon               = ([datetime]::FromFileTime(($_.LastLogon)))
                            OperatingSystem         = $_.operatingSystem
                            Version                 = $_.operatingSystemVersion
                            ServicePack             = $_.operatingSystemServicePack
                        })
                    }
                }
            }
        }
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
    Specifies the domain account to use.

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

    BEGIN {
        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $privExchangeAcl = $false
        $groupId = 'Exchange Windows Permissions'
        $objectSid = (Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter "(samAccountName=$groupId)" -Properties objectsid).objectsid
        $groupSid = (New-Object Security.Principal.SecurityIdentifier($objectSid, 0)).Value
        Write-Verbose "SID of the group 'Exchange Windows Permissions': $groupSid"
        if ($groupSid -and (Get-LdapObjectAcl -ADSpath $adsPath -Credential $Credential -Filter "(DistinguishedName=$defaultNC)" | ? { ($_.SecurityIdentifier -imatch "$groupSid") -and ($_.ActiveDirectoryRights -imatch 'WriteDacl') -and -not ($_.AceFlags -imatch 'InheritOnly') })) {
            $privExchangeAcl = $true
        }
        Write-Output $privExchangeAcl
    }
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
    Specifies the domain account to use.

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

    BEGIN {
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

        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $roleDictionary = @{2  = "MB"; 4  = "CAS"; 16 = "UM"; 32 = "HT"; 64 = "ET"}
        $properties = 'sAMAccountName', 'msExchCurrentServerRoles', 'networkAddress', 'versionNumber'
        $filter = "(|(objectClass=msExchExchangeServer)(objectClass=msExchClientAccessArray))"
        $configurationNC = $rootDSE.configurationNamingContext[0]
        $exchangeServers = Get-LdapObject -ADSpath "LDAP://$Server/$configurationNC" -Credential $Credential -Filter $filter -Properties $properties
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
            Write-Output ([pscustomobject] @{
                Fqdn            = ($exchServer.networkAddress | Where-Object -FilterScript {$_ -like "ncacn_ip_tcp*"}).Split(":")[1]
                Roles           = [string] ($roleDictionary.Keys | ?{$_ -band $exchServer.msExchCurrentServerRoles} | %{$roleDictionary.Get_Item($_)})
                Version         = "$($exchVersion.MajorVersion).$($exchVersion.MinorVersion).$($exchVersion.Build)"
                PrivExchange    = $privExchange
                'CVE-2020-0688' = $CVE20200688
                ProxyLogon      = $proxyLogon
            })
        }
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
    Specifies the domain account to use.

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

    BEGIN {
        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $adsPath = "LDAP://$Server/$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $legacyOS = '2000', '2003', '2008', 'ME', 'XP', 'Vista', 'Windows NT', 'Windows 7', 'Windows 8'
        $filter = ''
        foreach ($os in $legacyOS) {
            $filter += "(operatingsystem=*$os*)"
        }
        $filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2)(|$filter))"
        $properties = 'dnsHostname', 'samAccountName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack', 'LastLogon'
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
            Write-Output ([pscustomobject] @{
                    sAMAccountName = $_.samAccountName
                    ComputerName = $_.dnsHostname
                    OperatingSystem = $_.operatingSystem
                    Version = $_.operatingSystemVersion
                    ServicePack = $_.operatingSystemServicePack
                    LastLogon = ([datetime]::FromFileTime(($_.LastLogon)))
            })
        }
    }
}

Function Get-DnsRecord {
<#
.SYNOPSIS
    Get Active Directory-Integrated DNS (ADIDNS) records for a given zone.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-DnsRecord queries domain controller via LDAP protocol for DNS records.
    It is a slightly modified version of PowerView's Get-DomainDNSRecord by @harmj0y.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the domain account to use.

.PARAMETER ZoneName
    Specifies the DNS zone to query for records, defaults to Active Directory domain.

.EXAMPLE
    PS C:\> Get-DnsRecord -Server DC.ADATUM.CORP -Credential ADATUM\testuser
#>

    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneName
    )

    BEGIN {
        Function Local:Get-Name ([Byte[]] $Raw) {
            [Int] $Length = $Raw[0]
            [Int] $Segments = $Raw[1]
            [Int] $Index =  2
            [String] $Name  = ''
            while ($Segments-- -gt 0) {
                [Int]$segmentLength = $Raw[$Index++]
                while ($segmentLength-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }

        Function Local:ConvertFrom-DNSRecord ([Byte[]]$DNSRecord) {
            $rDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
            $updatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

            $ttlRaw = $DNSRecord[12..15]
            $null = [array]::Reverse($ttlRaw)
            $ttl = [BitConverter]::ToUInt32($ttlRaw, 0)

            $age = [BitConverter]::ToUInt32($DNSRecord, 20)
            if ($Age -ne 0) {
                $timestamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
            }
            else {
                $timestamp = '[static]'
            }

            $dnsRecordObject = New-Object PSObject

            switch ($rDataType) {
                1 {
                    $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
                    $data = $IP
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'A'
                }
                2 {
                    $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
                    $data = $NSName
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'NS'
                }
                5 {
                    $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
                    $data = $Alias
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'CNAME'
                }
                6 {
                    $data = $([Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'SOA'
                }
                12 {
                    $ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
                    $data = $ptr
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'PTR'
                }
                13 {
                    $data = $([Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'HINFO'
                }
                15 {
                    $data = $([Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'MX'
                }
                16 {
                    [string] $txt  = ''
                    [int] $segmentLength = $DNSRecord[24]
                    $Index = 25
                    while ($segmentLength-- -gt 0) {
                        $txt += [char]$DNSRecord[$index++]
                    }
                    $data = $txt
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'TXT'
                }
                28 {
                    $data = $([Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'AAAA'
                }
                33 {
                    $data = $([Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'SRV'
                }
                default {
                    $data = $([Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                    $dnsRecordObject | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
                }
            }
            $dnsRecordObject | Add-Member Noteproperty 'UpdatedAtSerial' $updatedAtSerial
            $dnsRecordObject | Add-Member Noteproperty 'TTL' $ttl
            $dnsRecordObject | Add-Member Noteproperty 'Age' $age
            $dnsRecordObject | Add-Member Noteproperty 'Timestamp' $timestamp
            $dnsRecordObject | Add-Member Noteproperty 'Data' $data
            Write-Output $dnsRecordObject
        }

        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            if (-not $PSBoundParameters['ZoneName']) {
                $ZoneName = $defaultNC -replace 'DC=' -replace ',', '.'
            }
            $adsPath = "LDAP://$Server/DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones,$defaultNC"
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    PROCESS {
        $filter = '(objectClass=dnsNode)'
        $properties = 'name', 'distinguishedname', 'dnsrecord', 'whencreated', 'whenchanged'
        Get-LdapObject -ADSpath $adsPath -Credential $Credential -Filter $filter -Properties $properties | ForEach-Object {
            $obj = $_
            if ($obj.dnsrecord -is [DirectoryServices.ResultPropertyValueCollection]) {
                $record = ConvertFrom-DNSRecord -DNSRecord $obj.dnsrecord[0]
            }
            else {
                $record = ConvertFrom-DNSRecord -DNSRecord $obj.dnsrecord
            }
            if ($record) {
                $record.PSObject.Properties | ForEach-Object {
                    $obj | Add-Member NoteProperty $_.Name $_.Value
                }
            }
            $obj | Add-Member NoteProperty 'ZoneName' $ZoneName
            Write-Output $obj | Select 'ZoneName','RecordType','Name','Data','Timestamp','WhenCreated','WhenChanged'
        }
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
                if (($_ -ne 'adspath') -and ($p[$_].count -eq 1)) {
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
