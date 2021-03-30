# ADMap

ADMap is a PowerShell tool for Active Directory reconnaissance.

## Functions

```
Get-LdapPassword                -   gets plaintext passwords from Active Directory
Get-PasswordPolicy              -   gets password policies defined in Active Directory
Get-KerberoastableUser          -   gets user accounts vulnerable to Kerberoast attack
Get-KerberosDelegation          -   enumerates enabled accounts granted with Kerberos delegation
Get-PrivExchangeStatus          -   gets PrivExchange exploitability regarding to Active Directory ACL
Get-ExchangeVersion             -   enumerates Exchange servers from Active Directory and check for exploitable vulnerabilities
Get-LegacyComputer              -   enumerates outdated Windows computers from Active Directory
Get-DnsRecord                   -   enumerates Active Directory-Integrated DNS records for a given zone
```
