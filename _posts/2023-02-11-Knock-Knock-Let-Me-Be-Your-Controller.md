---
date: 2023-02-06 23:48:05
layout: post
title: Knock Knock Let Me Be Your Controller
subtitle: Knock Knock Let Me Be Your Controller.
description: >-
  In this Blog, I've explained some scenarios which I've faced in AD assessment.
image: https://i.ibb.co/bbLMGmn/logo.jpg
optimized_image: https://i.ibb.co/bbLMGmn/logo.jpg
category: Active Directory
tags:
  - Active Directory
author: Ahmed Fatouh
paginate: true
published: false
---
Hello All, in this blog i will give you some scenarios which you will face at any Active directory Assessment.

### AS-REP Roasting

> **AS-REP roasting is a technique that allows retrieving password hashes for users that have Do not require Kerberos preauthentication property selected:**

![](https://i.ibb.co/1vcBDFr/1.png)

> **so lets assume that ther is some users in a corporate, like ahmed fatouh, khaled, reda, and so on, what if we need to make an compination of usernames to start the AS-REP Roasting attack.** 

- **Ahmed Fatouh will be (a.fatouh, afatouh, ahmed.f, ahmedfatouh) and so one with all users.**
- **lets assume we got some users with social engineering, lets go!**

 ```ruby 
impacket-GetNPUsers dc.test/ -no-pass -usersfile userslist.txt  -format john -dc-ip xx.xx.xx.xxx
```

![](https://i.ibb.co/HBv9PdZ/Inked-Inked2.jpg)

> **now let's assume we got some users and we dumped all things we need to escalate your privileges.**

> **first we have to get a user then we will use this user to get the administrator hash.**
> **using bloodhound I get the previous info.**
![](https://i.ibb.co/XxhXf1K/Inked3.jpg)






