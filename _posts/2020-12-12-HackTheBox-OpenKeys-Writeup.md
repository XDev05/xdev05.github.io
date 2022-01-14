---
date: 2020-12-12 23:48:05
layout: post
title: HackTheBox OpenKeys Writeup
subtitle: Hackthebox OpenKeys Writeup
description: >-
  in this blog i've explained how to solve OpenKeys machine in hackthebox
image: https://i.ibb.co/sg3rfZ2/logo.png
optimized_image: https://i.ibb.co/sg3rfZ2/logo.png
category: hackthebox
tags:
  - hackthebox
  - OpenKeys
author: Ahmed Fatouh
paginate: true
---


# []()Methodology

* Service Enumeration
* ByPass Authentication
* Privilege Escalation

# []()Nmap Scan

> as always, i’ll do nmap scan to find out which services running in this machine.

* 22/tcp --> ssh
* 80/tcp --> OpenBSD httpd

```ruby

# Nmap 7.80 scan initiated Sun Aug  2 00:16:08 2020 as: nmap -sC -sV -oN scan.txt 10.10.10.199
Nmap scan report for 10.10.10.199
Host is up (0.32s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).

```

> **as always i will check the web page first, let's go.**

![web-page](https://i.ibb.co/C00XtWT/webpage.png)

* this is a simple web page with a login form, so first let's do directory listing.

> let's run gobuster with this command: **gobuster dir -u http://10.10.10.199/ -w /usr/share/dirb/wordlists/common.txt**

```ruby

Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.199/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/10 21:56:27 Starting gobuster
===============================================================
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/includes (Status: 301)
/index.html (Status: 200)
/index.php (Status: 200)
/js (Status: 301)

```

> in the **includes directory** i found a swap file which contain a username.

![](https://i.ibb.co/TgkKdtG/swap-file.png)

* **so now we have username, let's return back to the login page to play with it.**

> **here is the login request.**

![](https://i.ibb.co/cXWyL33/LOGIN-REQUEST.png)

* in this point i tried some injection techniques but i failed, so i searched for OpenBSD Authentication Bypass and i found this [Blog](https://n3x0.com/2019/12/05/severe-auth-bypass-and-priv-esc-vulnerabilities-disclosed-in-openbsd/) and this [Blog](https://www.secpod.com/blog/openbsd-authentication-bypass-and-local-privilege-escalation-vulnerabilities/)

> **so now we know that we will Bypass the Authentication but how? let me explain to you.**

> **if an attacker specifies the username ‘-schallenge’ or ‘-schallenge:passwd’ for force passwd-style auth, it leads to successful authentication bypass.**

> **so let's check.**

![](https://i.ibb.co/6J3xrKx/1.png)

* **let's follow redirection.**

![](https://i.ibb.co/XL4dfM0/2.png)

> **nice error, this error give us hint, we need to specify the username in the cookies to Bypass the auth and reterive his data.**

* **so the request will be like this.**

![](https://i.ibb.co/ZdxMs5x/request-auth.png)

* **nice!**

![](https://i.ibb.co/tZ0Kdnn/rsa-key.png)

> **we got jennifer ssh private key.**

![](https://i.ibb.co/4mjN8Nh/done.png)

> **let's login now.**

# []() Jennifer Login && User Flag

```ruby

╭─xdev05@nic3One ~/Documents/HTB/OpenKeyS  
╰─➤  ssh -i jennifer_rsa jennifer@10.10.10.199 
Last login: Thu Dec 10 19:47:41 2020 from 10.10.14.151
OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

openkeys$ whoami;id;hostname;cat user.txt
jennifer
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
openkeys.htb
36ab21239a15c537bde90626891d2b10
openkeys$ 


```

* user done!

# []() root@openkeys.htb

> **in the same blogs i found a way to local privilege escalation.**

> in this point we will use CVE-2019-19520 or CVE-2019-19522 to gain **auth group** permissions.

> **follow this [Blog](https://packetstormsecurity.com/files/155572/Qualys-Security-Advisory-OpenBSD-Authentication-Bypass-Privilege-Escalation.html) or Upload this [script](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot) to the machine and run it.**


```ruby

openkeys# whoami;hostname;cat /root/root.txt 
root
openkeys.htb
f3a553b1697050ae885e7c02dbfc6efa
openkeys# 

```

* **cheers!**

 <script src="https://www.hackthebox.eu/badge/103789"></script>
