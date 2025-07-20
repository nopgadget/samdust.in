### Understanding PanOS

PanOS environment is much like Cisco IOS. The commands ran are somewhat like linux, but often is a completely different version of the command, or doesn't do the same thing. You can always press the question mark (?) button to show available commands, or tab button to show options for the command you have typed and/or autocomplete command arguments.

### Update

You can update via GUI, but often the latest updates aren't even displayed on GUI. These instructions are for PanOS CLI

```sh
admin@PA-VM> request content upgrade download latest
 Applications and Threats version: 8939-9248

admin@PA-VM> request content upgrade install version latest

admin@PA-VM> request system software info

admin@PA-VM> request system software check

Version                          Size    Released on          Downloaded
---------------------------------------------------------------------------
11.2.4                           786MB   2024/11/05 11:12:37  no
11.2.4-h2                        770MB   2024/12/04 16:10:27  no

admin@PA-VM> request system software download version 11.2.4-h2 # whatever the latest is, be sure to look at "Released on", like above 1.2.4 is older than 1.2.4-h2

admin@PA-VM> show jobs id 12 # run to check status, wait for it to complete
The required '11.2.0' base image must be loaded before this image can be loaded.  You do not have to install or run the base image, only download it.  Once the base is loaded, re-download your target image.

# repeated to download base image, then latest image.

admin@PA-VM> request system software install version 11.2.4-h2

# If you get the below error, update your content DB as shown in first command
# Error: Upgrading from 11.1.4 to 11.2.0 requires a content version of 8832 or greater and found 8790-8462.

Software installation of version 11.2.4-h2 successfully completed. Please reboot to switch to the new version.

admin@PA-VM> request restart system

# After restart, login service will be slower than ssh service. Might kill your shell before a time or two before you actually log in, this is normal for PA.
```

https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000CloaCAC
https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000CluOCAS


### Export Config & Device State

Can look at config for general overview of users, config, etc. Be on alert if you see unfamiliar users.


Create a SSH server on a machine that you trust, for future use.
```bash
sam@computer:~$ sudo apt install openssh-server
sam@computer:~$ sudo systemctl start ssh && sudo systemctl enable ssh
sam@computer:~$ sudo nano /etc/ssh/sshd_config # or vi, whatever

PermitRootLogin no
X11Forwarding no

sam@computer:~$ sudo systemctl reload ssh
sam@computer:~$ sudo systemctl status ssh

sam@computer:~$ sudo adduser ssh-throwaway

# Set a password that you will remember, save in group BitWarden.
# In my case, I used password '0*h!6LZt@kYvvMcrdxz'
```

```sh
admin@PA-VM> configure

admin@PA-VM# save config to BackupConfig.xml
admin@PA-VM# exit

# Make sure that you have a host running a ssh server. This should probably be a host or VM you trust to not go down
# Can also be done via tftp, but ssh server is safer and easier to setup.

admin@PA-VM> scp export configuration from BackupConfig.xml to ssh-throwaway@172.30.24.160:/home/ssh-throwaway/ # sub your user and IP


# When you need to import the config
admin@PA-220> scp import configuration from user@<scphost:/path
```


```
admin@PA-VM> scp export device-state to ssh-throwaway@172.30.24.160:/home/ssh-throwaway/

device_state_cfg.tgz                                                                   100% 2514    51.2KB/s   00:00
```

https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClJ9CAK

### Services

```
admin@PA-VM> show system services

HTTP       : Disabled
HTTPS      : Enabled
Telnet     : Disabled
SSH        : Enabled
Ping       : Enabled
SNMP       : Disabled

SNMP tends to have vulns associated, so disable if enabled. 

admin@PA-VM> configure
admin@PA-VM# set deviceconfig system service disable-snmp yes
admin@PA-VM# commit
```
### Syslog Forwarding (to Splunk)

https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring
https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClGwCAK
https://pan.dev/splunk/docs/


```
https://paloalto-ip/
Device > Log Settings > System > Add
Name: Splunk Forwarding

Forward Method > Panorama
Forward Method > Syslog > Add > New Syslog Server Profile
Name: Splunk-Syslog-Profile
Add
Name: Splunk, Syslog Server: Splunk IP, Transport: SSL
OK
```

![Splunk Forwarding Configuration](img/blog/splunk-forward.png)

Work-in-progress