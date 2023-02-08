---
date: 2023-02-06 23:48:05
layout: post
title: Hacking Core Banking, Is It Too Easy?!
subtitle: Hacking Core Banking, Is It Too Easy?!
description: >-
  In this Blog, I've explained some scenarios which I've faced while hacking some core banking applications.
image: https://i.imgur.com/1NUdPpx.png
optimized_image: https://i.imgur.com/1NUdPpx.png
category: Application Security
tags:
  - web security
  - sql injection
  - bug hunting
  - Broken Access Control
  - API Hacking
  - hackerone
author: Ahmed Fatouh
paginate: true
---

### Introduction

> **as Penetration Testers, all of us do a Pentest for core banking applications but there are some people who fear doing pentest for those applications so I'll Put some scenarios I've faced while doing pentest on core banking applications, let me describe what is Core banking.**

> **Core banking is a banking service provided by a group of networked bank branches where customers may access their bank account and perform basic transactions from any of the member branch offices.**

> **let me give you an example, you have an account in Bank A, and you want to send money to your friend which has an account in Bank B, so you will use an online banking application to send money from Bank A to Bank B.**

> **now i'll give some scenarios:**

### Scenarios

#### Scenario 1:-

lets assume you have an online bankin application which have some functions like see balance, send, receive and so on, and you go to check your balance, the request will be like this:
```ruby
{
 "Ammount":3232,
 "CurrenceyCode": 23123,
 "WalletID":, 132
 "LoginID":, 75656
 "SessionID": 5jlskgdhfsdg
 "UserName":fatouh
}
```
now we have some details, and a valid sessionID, as an attacker you can change the WalletID to any wallet of any user and see all info of this wallet, set the value of the username as NULL as there is no validation for it, or you use the same SessionID and change the client details to another and you will able to see all details of the client, also this for other functions like send, receive money, using the same sessionID I could able to dump all users Wallet info, send, receive money.
This is a simple scenario for online banking hacking, another scenario.

#### Scenario 2:-

you using the mobile application to transfer money from mobile number to another mobile number, the request will be like this:
```ruby
{
 "WalletID":2,
 "ClientTransferToMobileNumber":018083234
 "LoginID":23432
 "SessionID":sdfsdfsd
}
```
now simply change the ClientTransferToMobile number to attacker mobile with the same sessionID and you will able to receive money.

#### Scenario 3:-

if the client gave you the server IP in which they hosted their application, assume that you did nmap scan and you find PostgreSQL running on port 5432,
- you can simply bruteforce the password using the following module in Metasploit: ```auxiliary/scanner/postgres/postgres_login```
- if you were lucky like me, you will get the password, now you can get Remote code execution on the server using the following: 
```ruby
CREAT TABLE cmd_exec(cmd_out text);
copy cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```
and now you have rce on the server, very simple ha!.

Scenario 4:- 
let's assume you have the following code sample: 
```ruby
using System.Web;
using System.Web.Mvc;
public class ExampleController : Controller
{
 private static readonly.Log __Logger and so on
 [HttpGet]
 public void Log(string data)
 {
 if (data !=null)
 {
 _logger.info('Log :' + data);
 }
 }
}
```
this code is vulnerable to logging injection as the input should be like this
```ruby
if (data !=null)
{
 data = data.Replace('\n', '_').Replace('\r', '_')
 _logger.Info("Log": + data);
}
```

Cheers!

