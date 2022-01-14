---
date: 2020-08-15 23:48:05
layout: post
title: Arab Security Cyber WarGames 2020 RE Challenges Writeup
subtitle: Arab Security Cyber WarGames 2020 RE Challenges Writeup
description: >-
  in this blog i've explained how to solve openadmin machine in hackthebox
image: https://i.ibb.co/88K0xT7/logo.png
optimized_image: https://i.ibb.co/88K0xT7/logo.png
category: CTFs
tags:
  - CTFs
  - reverse engineering
author: Ahmed Fatouh
paginate: true
---


> This is the write up of the for the RE challenges in the ASC CTF qualification round. There was 2 RE chellenges.

# []() Check

* Type: Reverse
* Points: 600

> There are many different approaches to solve this challenge

> ![](https://i.ibb.co/10s9kp9/1.png)

> The guessing one, let's run **ltrace**

> ![](https://i.ibb.co/1vmDQGN/2.png)

* So it gets the **HOSTNAME environment variable** and it might compare it with **Machine**, next it gets the **USER environment** variable and compare it with **reenigne.**

> ![](https://i.ibb.co/bsYk7QY/3.png)

> Now what you need to do is change your **HOSTNAME** and **USER** environment variables to match what you found.

> ![](https://i.ibb.co/w7zPLRQ/4.png)

* It prints a base64 string so you just need to decode it.

> ![](https://i.ibb.co/g6CJHcd/5.png)

> Flag : **ASCWG{3nv_v4r5_4r3_u53ful}**


### []() The static analysis approach

> Following the **[×] Machine not OK.** string you will get to this if statement then printing **[o] Machine OK:** followed by a string so this string could be our **flag.**

> ![](https://i.ibb.co/kJHqmjT/6.png)

* The s variable is an array of char that is terminated with char **0** or the **null terminator**

> ![](https://i.ibb.co/Brmds3M/7.png)

> Now let's look at the sub11ED function and see what it does with our flag

> ![](https://i.ibb.co/XydjX42/8.png)

> It just takes the **flag and xor it with 0x92**, so the process can be repeated manually.

> ![](https://i.ibb.co/G3FQ5hR/9.png)

### []() The in depth approach

> I renamed some of the variables and functions to make sense. All XOR functions are followed by a number, the number is equal to the number that the data is xored with.

> ![](https://i.ibb.co/px9m6P4/10.png)

> Which means that after the xor the HOSTNAME variable is equal to **HOSTNAME** and **HostnameENV** equals the hostname environment variable.

> ![](https://i.ibb.co/qrYY7BS/11.png)

* And then checks **HostnameENV** with **Machine** and sets a flag to 1

> ![](https://i.ibb.co/5B5XCPp/12.png)

> The same as explained above, nothing new here.

> ![](https://i.ibb.co/V3HPMBX/13.png)

> Then if the environments variable **HOSTNAME, USER** are equal to **Machine, reenigne** respectively.

* you can also use a debugger and skip the last check as all the above code has nothing to do with the flag itself but you got my point


# []() DOOM

> We got  a 64-bit ELF, and it just takes the input and does nothing with it 

> ![](https://i.ibb.co/rm9D3Hr/14.png)

> So checking the main you can see that it just print doom and takes an input and that's all it does

> ![](https://i.ibb.co/xDQHN6Z/15.png)

> So clearly the flag isn't there upon checking the other function i was verifyFlag and printFlag which caught my interest, looking at the verifyFlag function as printFlag just print the variable being passed to it in the format flag format, so let’s fouce on verifyFlag.

> ![](https://i.ibb.co/nQcn6N7/16.png)

> It has some hard coded data like **s** and **v5** which are used for **RC4 decryption** i think.

> ![](https://i.ibb.co/bFkTV6f/17.png)

> Then it reads data from **string.txt**

> ![](https://i.ibb.co/Y7h8R9K/18.png)

> Then it hash the content of string.txt with md5 hash.

> ![](https://i.ibb.co/bdHMhXS/19.png)

> And then compare it with the output of the RC4 decryption and then it prints the **flag**.

* So let’s now use the debugger to check the **s1** and **s2** values but first let’s create a **string.txt** file.

> ![](https://i.ibb.co/fVgL0VZ/20.png)

> Break main and run the program then break **verifyFlag** and then set the **rip** to **verifyFlag**.

> ![](https://i.ibb.co/RYN8nBm/21.png)

> Set breakpoint at the address **0x000000000800167a**

> ![](https://i.ibb.co/XbbC5Gb/22.png)

> To check what are the values of the variables being passed

> ![](https://i.ibb.co/8Pnpst7/23.png)

> After checking the rax and rdx values with x/16x **(why 16? Because we know from the code that they are MD5 Hashes)**

> ![](https://i.ibb.co/mG2nc3D/24.png)

* Keep in mind that the string.txt file contains the number **1**
* So **rdx** = **c4ca4238a0b923820dcc509a6f75849b** (the hash of  number **1**)
* **rax** = **b9448dd62f8f39451767741f799c8d8b** (the hash of **apocolypsedoomsday**)

> FLAG: **ASCWG{apocolypsedoomsday}**

* cheers!















