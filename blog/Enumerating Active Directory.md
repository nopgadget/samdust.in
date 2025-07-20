http://distributor.za.tryhackme.com/creds
damien.horton
pABqHYKsG8L7

### Via Microsoft Management Console
```powershell
runas /netonly /user:damien.horton cmd.exe
```

MMC
File -> Add/Remove Snap Ins
All Active Directory
Change Forest / Domain to za.tryhackme.com
Right click "Users and Computers" in left pane and "view -> advanced features"
\
THM{Enumerating.Via.MMC}

### Via CMD

Usually when users have more than 10 group memberships, net user {user} /domain will fail to list them all

`net group {group} /domain`

### Password Policy Discovery
`net accounts /domain`
* see password policy

### Via Powershell
```powershell
Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *
```

```powershell
Get-ADGroup -Identity Administrators -Server za.tryhackme.com
```

```powershell
Get-ADGroupMember -Identity Administrators -server za.tryhackme.com
```

```powershell
get-aduser -identity annette.manning -properties * -server za.tryhackme.com | select DistinguishedName
```

CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com
2/24/2022 10:04:41 PM
-properties *

### Via WMI (Additional Research)
root\directory\ldap

### SharpHound
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs