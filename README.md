# ADMap

ADMap is a PowerShell tool for Active Directory reconnaissance.

## Functions

```
Get-DomainInfo                  -   gets basic information about a given Active Directory domain
Get-TrustRelationship           -   enumerates trust relationships defined in a given Active Directory domain
Get-PasswordPolicy              -   gets password policies defined in a given Active Directory domain
Get-PotentiallyVoidPassword     -   gets user accounts allowed to have void password
Get-LdapPassword                -   gets plaintext passwords from a given Active Directory domain
Get-KerberoastableUser          -   gets user accounts vulnerable to Kerberoast and ASREPRoast attacks
Get-KerberosDelegation          -   enumerates enabled accounts granted with Kerberos delegation
Get-VulnerableSchemaClass       -   gets vulnerable schema classes that can be used to create arbitrary objects
Get-PrivExchangeStatus          -   gets PrivExchange exploitability regarding to Active Directory ACL
Get-ExchangeVersion             -   enumerates Exchange servers from Active Directory and check for exploitable vulnerabilities
Get-ADCSServer                  -   enumerates ADCS Certificate Authority servers from Active Directory
Get-LegacyComputer              -   enumerates outdated Windows computers in a given Active Directory domain
Get-DnsRecord                   -   enumerates Active Directory-Integrated DNS records for a given zone
```
