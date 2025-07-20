## Tooling

- [ ] Tooling distribution
	- Proxy (e.g. squid proxy) on victim network, set up on internet-facing box then connect to that proxy. Allows OS updates and tooling pulls as necessary.
	- SMB Share, can access tooling via \\\\ip\\share, net share
	- Central file location on Blue Teamer's Laptop
- [ ] Install Sysinternals
	- Autoruns
	- Procmon
	- LogonSessions.exe
		- alternative `query user, or Get-WMIObject -Query “select * from Win32_UserProfile where special=false and loaded=true”`
	- ShareEnum
		- Alternative Get-NetShare (PowerView) or net share
- [ ] https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook
	- Especially PowerUp
- [ ] PowerView
	* https://powersploit.readthedocs.io/en/latest/Recon/
	* https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
* [ ] BloodHound
	* Ingestion: Sharphound, SharpHound.ps1, bloodhound-python
	* Neo4j database setup takes a few minutes, just `sudo neo4j console` then visit the web interface and change default password
## Manual Enumeration

 Powershell History - Check at the beginning to see how services / configurations were made and installed.
* `type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

```powershell
net command - run just 'net' to see options

# notable options
net accounts - password & lockout policy (you want to lock out bad guys)
net user (only local users. for domain users, do /domain flag)
net localgroup
net share
```

#### Find Admin Users
```cmd
net localgroup Administrators
```

Permissions for C:\ Drive (Can be adapted for net shares as well)
```powershell
(get-acl \).access | ft # (ft is format-table shortened, can always get-alias ft to know what command it is)
```

### Closing Ports
Get PID and Port for Listening TCP Connections (Identify Revshells)
```powershell
Get-NetTCPConnection -State Listen | # Can remove listening state for all including current connections
Select-Object -Unique OwningProcess, LocalPort |
ForEach-Object {
    try {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction Stop
        [PSCustomObject]@{
            PID         = $_.OwningProcess
            Port        = $_.LocalPort
            ProcessName = $proc.ProcessName
        }
    }
    catch {
        # Handle any processes that have exited or can't be retrieved
        [PSCustomObject]@{
            ProcessName = 'N/A'
            PID         = $_.OwningProcess
            Port        = $_.LocalPort
        }
    }
} |
Sort-Object -Property Port |
Format-Table -AutoSize
```
## Powershell Hacks

```powershell
# wget equivalent
wget http://tooling.com/tool.exe -outfile tool.exe
```

### Firewall
```
WF.msc
```

### BYU Script Ripoffs

#### Change

```powershell
$COMPUTERS = Get-ADComputer -Filter * | % {$_.name} 
Invoke-Command -ComputerName $COMPUTERS -ScriptBlock {
# For this part, need to be domain admin so that you can run the commands on all machines on the network via winrm. If you can't do that, just remove the lines on the outside of the brackets

Write-Host "1. Start windows defender and change startup to auto" -ForegroundColor Blue
	Set-Service -Name Windefend -Status Running -StartupType Automatic 

Write-Host "2. Enable real-time monitoring" -ForegroundColor Blue
	set-MpPreference -DisableRealtimeMonitoring $False

Write-Host "3. Enable firewall" -ForegroundColor Blue
	Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

Write-Host "4. update antivirus signatures" -ForegroundColor Blue
	Update-MpSignature

Write-Host "5. Deactivate guest account" -ForegroundColor Blue
	Disable-LocalUser -Name "Guest"
	Disable-LocalUser -Name "Administrator"

Write-Host "6. Turn off smbv1" -ForegroundColor Blue
	Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

Write-Host "7. Updates with community module" -ForegroundColor Blue
	Install-Module PSWindowsUpdate 
	Get-WindowsUpdate -AcceptAll -Install -AutoReboot 

Write-Host "8. Confirm updates using old method" -ForegroundColor Blue
	wuauclt /detectnow /updatenow

Write-Host "9. Disable ps remoting" -ForegroundColor Blue
	Disable-PSRemoting
Write-Host "10. Stop PS remoting" -ForegroundColor Blue
	Get-Service | Where-Object Status -eq "Running"
	set-service winrm -Status Stopped -StartupType Disabled


} | Tee-Object -file CHANGE-script.txt
```

#### Domain Info

```powershell
# For each of these, the select-object clause is just for organization, you can do everything without it.

Invoke-Command -ScriptBlock {

Write-Host "DOMAIN NAME" -ForegroundColor Blue
Get-ADDomain | Select-Object Name, dnsroot, userscontainer


Write-Host "DC" -ForegroundColor Blue
Get-ADDomainController | Select-Object Name, OperatingSystem, ldapport, ipv4address


Write-Host "Group info" -ForegroundColor Blue
get-adgroup -Filter * | Select-Object Name, GroupScope, GroupCategory, DistinguishedName | sort name |ft


Write-Host "GPO" -ForegroundColor Blue
get-gpo -all | Select-Object displayname, domainname, owner,gpostatus, description, id | ft


Write-Host "ADMINS" -ForegroundColor Blue
Get-ADGroupMember administrators | Select-Object Name, objectclass, samaccountname | ft


Write-Host "Users" -ForegroundColor Blue
get-aduser -Filter * | sort name | Select-Object Name, enabled, objectclass, DistinguishedName



Write-Host "COMPUTERS (Use these for info.ps1 script for invoke command/remoting to get more info)" -ForegroundColor Blue

Get-ADComputer -Filter * -Properties ipv4Address, OperatingSystem | Select-Object Name, IPv4Address, OperatingSystem, Enabled | ft


} | Tee-Object -file DOMAIN-INFOMATION.txt
```

### Logging
```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force

# Both important for identifying what powershell is being ran on boxes
```
### Set Proxy

```powershell
netsh winhttp set proxy 1.1.1.1:1337 bypass-list="localhost,127.0.0.1" # include any IPs or domains you don't want going through proxy in bypass-list
```

### Change Password

Avoid putting passwords in command line if possible (use powershell variable)

```powershell
$password = Read-Host "Enter the new password" -AsSecureString
# Set AD User Pass
set-adaccountpassword -identity "user_to_change" -reset -newpassword $password
# Set Local User Pass
Set-LocalUser -Name "user_to_change" -Password $password
```

## GUI Options

### Group Policy Editor

### Users and Groups Editor

### Policies

```
secpol
```
#### Password Policy
- Open Account Policies > Password Policy
- Enforce password history: 7
- Maximum password age: 91
- Minimum password age: 14
- Minimum password length: 14
- Password must meet complexity requirements: Enabled

#### Account Lockout Policy
- Open Account Policies > Account Lockout Policy
- Account lockout threshold: 10
- Account lockout duration: 10
- Reset account lockout counter after: 10
- Allow Administrator account lockout: enabled

### Update Windows Apps

```
winget update --all
```
