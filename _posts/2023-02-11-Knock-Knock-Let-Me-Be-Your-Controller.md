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

### Abusing Active Directory Permissions

> **The user we've owned is the Owner of the Network Audit group, so we will add him to the group, then he will Have GenericWrite Permissions to the next user we want.**

> **Let me give you a brief about the Active Directory ACLs/ACEs:
> Active Directory objects such as users and groups are securable objects and DACL/ACEs define who can read/modify those objects (i.e change account name, reset password, etc). 
> An example of ACEs for the "Domain Admins" securable object can be seen here:**
> ![](https://i.ibb.co/QkPk26G/1111.webp)

> **Some of the Active Directory object permissions and types that we as attackers are interested in:**
- **GenericAll** - full rights to the object (add users to a group or reset user's password)
- **GenericWrite** - update object's attributes (i.e logon script)
- **WriteOwner** - change object owner to attacker controlled user take over the object
- **WriteDACL** - modify object's ACEs and give attacker full control right over the object
- **AllExtendedRights** - ability to add user to a group or reset password
- **ForceChangePassword** - ability to change user's password
- **Self (Self-Membership)** - ability to add yourself to a group

> **so we need first to add the user we have to the Network Audit group after being in the group we will have GenericWriet Permission on the next user.**
> **First step lets fire up our windows server, import ADModule and PowerView.**

> **lets execute the following commands in our powershell:**
> ![](https://i.ibb.co/QY1ZK9N/pss1.jpg)
> ![](https://i.ibb.co/7xDtwST/pss2.jpg)

> **now lets get new TGT for the user we have.**

> ![](https://i.ibb.co/rGpBnWX/ATTACK1.jpg)

> **lets manauplate the msDS-KeyCredentialLink of a target user/computer to obtain full control over that object and Add KeyCredential for the user which have high privileges.**

> ![](https://i.ibb.co/StvfP3g/attack2.jpg)

> **now lets import the KRB5CCNAME and login with evil-winrm**

> ![](https://i.ibb.co/Lhw0tTF/attack3.jpg)


#### Pre-requisites for this attack are as follows
- **the target Domain Functional Level must be Windows Server 2016 or above.**
- **the target domain must have at least one Domain Controller running Windows Server 2016 or above.**
- **the Domain Controller to use during the attack must have its own certificate and keys (this means either the organization must have AD CS, or a PKI, a CA or something alike).**
- **the attacker must have control over an account able to write the msDs-KeyCredentialLink attribute of the target user or computer account.**

### Local Privilege Escalation Using KrbRelay With Shadow Credentials.









