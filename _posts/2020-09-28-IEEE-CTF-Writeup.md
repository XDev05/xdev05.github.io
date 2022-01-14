---
date: 2020-05-02 23:48:05
layout: post
title: IEEE Olympics CTF Challenges Writeup
subtitle: IEEE Olympics CTF Challenges Writeup
description: >-
  in this blog i've explained how i and my team solved IEEE Olymbics CTF challenges.
image: https://i.ibb.co/YPR3X9G/logo.png
optimized_image: https://i.ibb.co/YPR3X9G/logo.png
category: CTFS
tags:
  - ctfs
  - web security
  - forensics
  - reverse engineering
author: Ahmed Fatouh
paginate: true
---



> **hello friends, this is My writeup for IEEE CTF Misc & RE & Forensics & Web writeups**.

# []() Foreniscs

![easy](https://i.ibb.co/MsX3xL7/easy.png)

* this challenge was very easy, i checked it with binwalk and i found that there is hidden photo's, then i extracted them and with exiftool i got the flag.

> You can download the challenge from here [EASY](https://filebin.net/3z6ni0dvk2oj9rdn/EASY.dd?t=begirmoz).

* let's start with **binwalk**

> **binwalk EASY.dd**

![](https://i.ibb.co/XS7Hrwm/easy-binwalk.png)

* now we have 4 photos in this dd image, let's extract them now.

> **binwalk --dd='.*' EASY.dd**

* i got this file **_EASY.dd.extracted** let's open it now.

![](https://i.ibb.co/1mvcHbR/extracted.png)

> now we need to check all of them with **exiftool**

* exiftool * 

![](https://i.ibb.co/hmvppZq/comment.png)

* there is a Comment!

> **Comment                         : VRRR{Gu!f_vf_Gur_sy@t_T00q-W0o}**

* looks like a flag!, yes this is our flag but it's encrypted with **Rot** and you can decrypt it with this [website](https://www.dcode.fr/rot-cipher)

![](https://i.ibb.co/0tmLsbn/flag.png)

> **Flag: IEEE{THSISTHEFLGGDJB}**

# []() Misc Challenges

# []()1.Caesar salad

![](https://i.ibb.co/XtnxwQR/easy.png)

> **from the challenge name i thought that this a Caesat Cipher but it was, Rail Fence Cipher, i tried all the Ciphers in this website til i got the flag.**

* use this [website](https://cryptii.com/pipes/caesar-cipher) to decrypt the string.

![](https://i.ibb.co/fqxbJpq/flag1.png)

> **Flag: IEEE{CaesarAintH4rd}**

# []()2.Uns3cure

![](https://i.ibb.co/vYPJgGX/unsecure.png)

> we got a pcap file and i opened it with wireshark and it's so easy to find the plaintext password, you can download the file from [here](https://filebin.net/3z6ni0dvk2oj9rdn/unsecure.pcap?t=3muyooly)

* open wireshark and look carefully with me

![](https://i.ibb.co/x5QrKSB/packet.png)

> **in this packet we can see that there is someone tell anotherone to login with ssh to make something.**

![](https://i.ibb.co/gghRpbQ/flag.png)

> **in this packet we found a plaintext with the same name of the challenge and we can confirm that this is the right password from the next packet.**

![](https://i.ibb.co/9NhBs0Y/loggedin.png)

* Login successful!

> **Flag: IEEE{so_Uns3cure}**

# []()3.warm up

![](https://i.ibb.co/Gs7wTpX/warmup.png)

> **we hava base64 hash and when we decrypt it i got another md5 hash, but we need to fix the hash as mensioned in the description of the challenge.**

![](https://i.ibb.co/RC3vzM6/base64.png)

* after analyse this hash i optain that this a hex value from **a-f** so we need to delete the char **h** and **z** to get the right md5 hash

> **False md5 hash: 482c811dha5d5b4bc6d497ffa98491ze38**

> **Correct md5 hash: 482c811da5d5b4bc6d497ffa98491e38**

![](https://i.ibb.co/mD1VSgB/flagmd5.png)

> **Flag: IEEE{password123}**

# []()4.Brute Me

![](https://i.ibb.co/hLRVjM1/bruteme.png)

* You can download the file from [here](https://filebin.net/3z6ni0dvk2oj9rdn/flag.zip?t=55c8jhxy)

> i just cracked tha password and got the flag.

> **fcrackzip -u -v -D -p /usr/share/wordlists/rockyou.txt flag.zip**

* **Password: sainsburys**

![](https://i.ibb.co/C7kzNYk/brute-flag.png)

> **Flag: IEEE{Easy_Brute}**

* nice!, we are done from the Misc now, let's go to the Web now.

# []() Web Challenges

# []()1. S3ssion master 

> **in this challenge we will play with the session cookie to get admin privilege to read the flag.**

![](https://i.ibb.co/Q8ZZzjm/sessionmaster.png)

* challenge [link](http://207.154.231.228:3000/)

* let's go

![](https://i.ibb.co/m0PDSwQ/suber.png)

* nothing here, so let's fireup burpsuite and see what we can do.

![](https://i.ibb.co/mHC5j6y/burp.png)

> i played with the session but i can't figure what is it and how can we got the admin cookie until i see hint for this challenge.

![](https://i.ibb.co/34bHvq3/hint.png)

* so now we know that we need to bruteforce hidden directory.

> **gobuster dir -u http://207.154.231.228:3000/ -w /usr/share/dirb/wordlists/common.txt -s 200,301**

```ruby

╭─xdev05@nic3One ~/Downloads/IEEE/writeup  
╰─➤  gobuster dir -u http://207.154.231.228:3000/ -w /usr/share/dirb/wordlists/common.txt -s 200,301
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://207.154.231.228:3000/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,301,302
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/09/28 09:07:37 Starting gobuster
===============================================================
/sess (Status: 301)
===============================================================
2020/09/28 09:08:05 Finished
===============================================================

```

> **after opening this dir i noticed that, every chat for dir and the file in the latest dir are cookie, let's see.**

![](https://i.ibb.co/qnjZf9f/usercookie.png)

> **so the other dir will ne the session for the admin let's see.**

![](https://i.ibb.co/C85Trz0/admin.png)

> **if we compined the dirs and the name of the file in it we will optain the admin session.**

> **admin session: ry t2 w3 nd 2n xx on rd bq d7 qh 1o k71bzpev8zpa7vgnn24db4m4imvrhzo1zatw10iv**

* so this is the session : **ryt2w3nd2nxxonrdbqd7qh1ok71bzpev8zpa7vgnn24db4m4imvrhzo1zatw10iv**

* go to burp now and put it.

![](https://i.ibb.co/tsPFbgS/adminflag.png)

> **Flag: IEEE{wh0 473 my c00k13?}**

# []()2.S3cure uploader 

![](https://i.ibb.co/b34MSPJ/secure.png)

* **uploader.php**

```ruby

<?php
if(isset($_GET["upload"])) {
$target_dir = "uploads/";
$vars = explode(".", $_FILES["FileToUpload"]["name"]);
$filename=$vars[0];
$ext = $vars[1];
//randomizing file name
$time = date('Y-m-d H:i:s');
$new_name = md5(rand(1,1000).$time.$filename."0x4148fo").".".strtolower(pathinfo(basename($_FILES["FileToUpload"]["name"]),PATHINFO_EXTENSION));
$filename=explode(".", $_FILES["FileToUpload"]["name"])[0];
$ext = $filename=explode(".", $_FILES["FileToUpload"]["name"])[1];
$target_file = $target_dir . "$new_name";
// Check if file already exists
if (file_exists($target_file)) {
  echo "File already exists.";
  $uploadOk = 0;
  die();
}
// Check file size
if ($_FILES["FileToUpload"]["size"] > 500000) {
  echo "File is too large.";
  $uploadOk = 0;
  die();
}
$uploadOk = 1;
$check = getimagesize($_FILES["FileToUpload"]["tmp_name"]);
if($check !== false) {
    $uploadOk = 1;
} else {
    echo "File is not an image.";
    $uploadOk = 0;
    die();
  }
}
move_uploaded_file($_FILES["FileToUpload"]["tmp_name"], $target_file);
if(strtolower(pathinfo(basename($_FILES["FileToUpload"]["name"]),PATHINFO_EXTENSION))=="jpg"){
echo "File uploaded successfully to $target_file";
}
else{
	die("Invalid file type");
}
?>

```

* **hashs.py**

```ruby

#!/usr/bin/python
import os

import hashlib

date = "2020-09-27 21:25:01"
filename = "shell"
key = "0x4148fo"
print(key)
with open("final.txt", 'w') as f:
	for i in range(1,1001):
		string = str(str(i)+date+filename+key).encode('utf-8')
		hash = hashlib.md5(string).hexdigest()
		print('{}'.format(hash), file=f)

```

# []() S3cure uploader Walkthrough

[![Video](https://i.ibb.co/b34MSPJ/secure.png)](https://www.youtube.com/watch?v=ktoYt_myWBI&t=2s)

# []() Reverse Challenges

# []()1.Dot Free

![](https://i.ibb.co/8sNXzNR/dotfree.png)

> **You can download the program from here [rev.exe](https://filebin.net/11vifdnxstdrcjwq/r3v.exe?t=plxeqb1z)**

* **Running the application it asks for an input**

![](https://i.ibb.co/wK3GxjZ/ask.png)

> **So let's use dnspy to decompile and see the code.**

![](https://i.ibb.co/QK95VdC/decom.png)

> **Flag: IEEE{Free_Points_4_u}**

# []()2.Trivia fun

![](https://i.ibb.co/SBXhJmx/triv.png)

> **You can download the program from here [trivia.exe](https://filebin.net/11vifdnxstdrcjwq/Trivia.exe?t=9p0zlpvv)**

* **It’s a multistep challenge which is quite fun.**

> **The first one is asking for a username and password.**

![](https://i.ibb.co/YBQk4BS/triviafun.png)

> **It’s .NET so let’s use dnspy to get them.**

* After looking at the source code i realised that the application has anti **debugging techniques** which is implemented in all of these classes **Program, Question, Trivia_Form**

![](https://i.ibb.co/fpBXY8v/dnspy.png)

* Which simply checks if a debugger is attached or if dnspy is running if so it simply doesn’t continue executing, so let’s remove these pieces of code to make it easier for us later on.

> **remove the code by right clicking and then edit the class then just remove the anti debugging code and compile and save**

#### []()First step:

> **Now we can solve the first step which is the username and password, which the code responsible for validating them is in Trivia_Form.**

![](https://i.ibb.co/2MVJ4jp/firststep.png)

* So it checks if the username matches this regex [^([A-Z0-9]{5}-){4}[A-Z0-9]{5}$] you can use this [site](https://regex101.com/) understand this regex,and it checks if the sum of the password ascii values = 1930.

> **Username = AAAAA-AAAAA-AAAAA-AAAAA-AAAAA,  which matches the regex.**
>
> **Password: zzzzzzzzzzzzzzzd,  their sum of the ascii value = 1930**

#### []()Seconed step:

![](https://i.ibb.co/DM8MR6B/seconed.png)

> **Solving the second step, which is the code responsible for validating the answer is in Qs_l1.**

![](https://i.ibb.co/PzddTWd/seco.png)

> **Let’s write a script to bruteforce the answer:**

```ruby

import string
enc = "Gu4g_J0hyq_o3_Mn_Z4GpU"
alpha = string.ascii_letters
ans = ""
i = 0
while(i<22):
  if((ord(enc[i])>= 97 and ord(enc[i])<= 122) or (ord(enc[i])>= 65 and ord(enc[i])<= 90)):
    for c in alpha:
      if (ord(c)>= 97 and ord(c)<= 122):
        if (ord(c) > 109):
          if(chr(ord(c) - 13) == enc[i]):
            ans += c
            break
        else:
            if(chr(ord(c) + 13) == enc[i]):
              ans += c
              break
      elif (ord(c)>= 65 and ord(c)<= 90):
        if (ord(c) > 77):
          if(chr(ord(c) - 13) == enc[i]):
            ans += c
            break
        else:
          if(chr(ord(c) + 13) == enc[i]):
            ans += c
            break
  else:
    ans+=enc[i]
  i+=1
print(ans)

```

> **The answer is: Th4t_W0uld_b3_Za_M4TcH**

#### []()Third step:

![](https://i.ibb.co/Ttnbyb1/third.png)

> **Solving the second step, which is the code responsible for validating the answer is located in Qs_l2.**

![](https://i.ibb.co/9w3qq8C/thirrdpic.png)

> **Let’s try to break it to understand it better.**

![](https://i.ibb.co/3TsfNST/break.png)

> **It just makes sure that the answer length is divisible by 3 and then divides it into 3 different arrays after converting them to their ascii equivalent.**

![](https://i.ibb.co/F5xxGzg/convert.png)

> **Create the xor key by shifting with different values.**

![](https://i.ibb.co/VjT7TNz/xor.png)

> Xor the answer with the keys and adding some values after.then concatenate all of them and compare it with: **X5Q;DU~<{6p`87)[`ad1.**

* So to understand it better let’s say if:
1.enc = answer ^ key + value
2.Then: answer = (enc - value) ^ key

> **Let’s write a script to get the answer**

```ruby

using System;
using System.Linq;
class Trivia {
    int[] convert_carr_iarr(char[] carr)
		{
			int[] array = new int[carr.Length];
			for (int i = 0; i < carr.Length; i++)
			{
				array[i] = (int)carr[i];
			}
			return array;
		}
	char[] convert_iarr_carr(int[] carr)
		{
			char[] array = new char[carr.Length];
			for (int i = 0; i < carr.Length; i++)
			{
				array[i] = (char)carr[i];
			}
			return array;
		}
 
	public string get_answer(string answer)
	{
		while (answer.Length % 3 != 0)
		{
			answer += "=";
		}
		int[] array;
		int[] array2;
		int[] array3;
		array = this.convert_carr_iarr(answer.Substring(0, answer.Length / 3).ToCharArray());
		array2 = this.convert_carr_iarr(answer.Substring(answer.Length / 3, answer.Length / 3).ToCharArray());
		array3 = this.convert_carr_iarr(answer.Substring(2 * answer.Length / 3, answer.Length / 3).ToCharArray());
		int[] array4 = new int["Z09CWQl".Length];
		int[] array5 = new int["Z09CWQl".Length];
		int[] array6 = new int["Z09CWQl".Length];
		for (int i = 0; i < "Z09CWQl".Length; i++)
		{
			int num = (int)"Z09CWQl"[i];
			array4[i] = num >> 3;
			array5[i] = num >> 4;
			array6[i] = num >> 2;
		}
		for (int j = 0; j < array.Length; j++)
		{
			array[j] ^= array4[j];
		}
		for (int k = 0; k < array2.Length; k++)
		{
			array2[k] = ((array2[k]-6) ^ array5[k]);
		}
		for (int l = 0; l < array3.Length; l++)
		{
			array3[l] = ((array3[l]-8) ^ array6[l]);
		}
		return string.Join<char>("", this.convert_iarr_carr(array).ToList<char>().Concat(this.convert_iarr_carr(array2).ToList<char>()).Concat(this.convert_iarr_carr(array3).ToList<char>()));
	}
  public static void Main() {
      string enc_answer = "X5Q;DU~<{6p`87)[`ad1.";
      Trivia h = new Trivia();
      string ans = h.get_answer(enc_answer);
      Console.WriteLine(ans);
 
  }
}

```

> **The answer is: S3V3N_s3v3n_777_VII==**

![](https://i.ibb.co/DzY1kbY/welldone.png)

> **After solving all the questions it says to look at the code so let’s check the code.**

![](https://i.ibb.co/QbkqT28/bb.png)

> **So it decrypts 'whoami' so let's create a breakpoint and check what does it return.**

![](https://i.ibb.co/SdTw3Fx/whoami.png)

> **Just set a breakpoint before returning to get the result value.**

![](https://i.ibb.co/CQCFxH5/result.png)

> **Flag: Flag{To_P4tch_0r_Not_To_P4tch}**

* Cheers!
