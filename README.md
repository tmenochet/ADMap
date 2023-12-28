# ADMap

ADMap is a PowerShell tool for Active Directory reconnaissance.

## Functions

```
Get-DomainInfo                  -   gets basic information about a given Active Directory domain
Get-TrustRelationship           -   gets trust relationships defined in a given Active Directory domain
Get-LdapPasswordPolicy          -   gets password policies defined in a given Active Directory domain
Get-GPPasswordPolicy            -   gets password policies defined in Group Policy files of a given Active Directory domain.
Get-PotentiallyEmptyPassword    -   gets user accounts allowed to have an empty password
Get-PreCreatedComputer          -   gets computer accounts that have never been used (password may be the hostname or empty)
Get-LdapPassword                -   discovers plaintext passwords from a given Active Directory domain
Get-KerberoastableUser          -   gets user accounts vulnerable to Kerberoast and ASREPRoast attacks
Get-KerberosDelegation          -   gets accounts granted with Kerberos delegation
Get-ServicePrincipal            -   discovers Kerberos services by searching for SPNs
Get-GPUserRightsAssignment      -   gets user rights assignments defined in Group Policy files of a given Active Directory domain.
Get-VulnerableSchemaClass       -   checks for vulnerable schema classes that can be used to create arbitrary objects
Get-PrivExchangeStatus          -   checks PrivExchange exploitability regarding to Active Directory ACL
Get-ExchangeServer              -   gets Exchange servers from a given Active Directory domain and check for exploitable vulnerabilities
Get-ADCSServer                  -   gets ADCS Certificate Authority servers from a given Active Directory domain
Get-ADCSCertificateTemplate     -   gets ADCS certificate templates from a given Active Directory domain and check for exploitable vulnerabilities
Get-SCCMServer                  -   gets SCCM servers from a given Active Directory domain
Get-LegacyComputer              -   gets outdated Windows computers from a given Active Directory domain
Get-DomainDnsRecord             -   gets Active Directory-Integrated DNS records for a given zone
Get-DomainSubnet                -   gets subnets defined in a given Active Directory domain
```
