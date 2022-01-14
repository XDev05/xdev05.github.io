---
date: 2020-09-19 23:48:05
layout: post
title: CyberTalents National CTF 2020 - RE Challenges Writeup
subtitle: CyberTalents National CTF 2020 - RE Challenges Writeup
description: >-
  in this blog i've explained how i and my team solved Reverse engineering challenges in CyberTalents CTF.
image: https://i.ibb.co/ZzsyQTk/logo.png
optimized_image: https://i.ibb.co/ZzsyQTk/logo.png
category: CTFS
tags:
  - CyberTalents
  - reverse engineering
  - ctf
author: Ahmed Fatouh
paginate: true
---


# []() RE Challenge 1 - Isolation

![isolation](https://i.ibb.co/sbBBTPh/isolation.png)

* You can download the Challenge from this [link](https://hubchallenges.s3-eu-west-1.amazonaws.com/Reverse/isolation.apk)

> **Description: Developer think That the real Hacker Does not need any buttons to get the flag.**

* when running the app we see that it asks for a Username and a Password but as the description says there is no buttons to login.

![](https://i.ibb.co/D9bPD6h/1.png)

> **so lets open bytecode viewer and see the decompiled version of the app to see the main activity.**

![](https://i.ibb.co/5M9pXwx/2.png)

* **nothing is interesting here but we can see Secretbox looking interesting as calling the library and setting text view.**

![](https://i.ibb.co/z78mtPT/3.png)

* so my initial thought was decompiling the app change the main activity to run the library and setting the text view as secretbox, but I couldn't make it to work, 
after a while my friend [Elshinbary](https://n1ght-w0lf.github.io/) pointed out to me that u can change the Main activity from the AndroidManifest.xml <br>
so let's try that as also the name of the installed apk is otherside.<br>
so what you need to do is decompile the apk with apk easy tool and change the Main activity from the AndroidManifest.xml.<br>

> From
> ![](https://i.ibb.co/bRWj1qZ/4.png)

> To
> ![](https://i.ibb.co/sKjmS5b/5.png)

> **and compile it again so after running the new version we will see the flag.**

> ![](https://i.ibb.co/tXtLHCn/6.png)

# []() Another Solution

> my friend told me that we can run command from edb shell to call any activity like **SecretBox** which will give us the flag.

* We can start any activity using a simple command in adb shell.

* Launch your adb shell using normal steps

> **am start -n yourpackagename/.activityname**

> **am start -n com.cybertalents.otherside/.SecretBox**

![](https://i.ibb.co/f8qQzgC/another.jpg)

![](https://i.ibb.co/0Xd2LgS/flag.jpg)


# []() RE Challenge 2 - Silver ASM

![](https://i.ibb.co/dg7VnYX/SILVER.png)

> **Description: the flag is the parameter of the function int he following format ("FLAG{0_%X_0}" % parmter)**

* You can download the Challenge from this [link](https://hubchallenges.s3-eu-west-1.amazonaws.com/Reverse/Silver_ASM.asm)

* **This is a Assembly file so let's break it down.**

```ruby

mov     DWORD PTR [rbp-4], edi
mov     edx, DWORD PTR [rbp-4]

```

> **moves edi to edx.**

```ruby
mov     eax, edx
add     eax, eax
add     eax, edx

```

> **moves edx to eax and do 2 add operations which is equal to eax=3*eax.**

```ruby
sal     eax, 2
```

> **which is left shifting eax by to bits or multiplying eax by 4, eax = 4*eax.**

```ruby
sub     eax, 3571200
cmp     eax, 0

```

* **sub eax by 3571200 or eax = eax - 3571200, and compare it with zero.**

* **by doing some math we can tell that (3*eax)x(4*eax)-3571200=0.**

* so eax = 297600, which is the same as edi.<br>

```ruby

fx:
        push    rbp
        mov     rbp, rsp
        mov     DWORD PTR [rbp-4], edi
        mov     edx, DWORD PTR [rbp-4]
        mov     eax, edx
        add     eax, eax
        add     eax, edx
        sal     eax, 2
        sub     eax, 3571200
        cmp     eax, 0
        setbe   al
        movzx   eax, al
        pop     rbp
        ret

```

* the flag is as specified in the description so we need to convert it to HEX.<br>

* the flag: **FLAG{0_48a80_0}**

* h00l19an$

* cheers!



