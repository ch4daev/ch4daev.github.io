---
layout: post
title: "Socks5Systemz"
date: 2023-12-18 18:20:11
tags : [malware,botnet,windows]
---

Loader : [Malware Bazaare](https://bazaar.abuse.ch/sample/22fdfde16d444cb9abe26e5f06cc4d7b72b98499a3819240615fef58cf6b41e5/)

Unpacked files : [Unpac.me](https://www.unpac.me/results/0bb17dae-7192-42df-aa90-c14215b1a661?hash=d380580f5ee79d082f97c198ffc5185abefcc539a1e49f94ae208589605aaba1#/)

Dumped module : [dump here](/posts_assets/socks5systemz/svgarateex_01785000.bin)

# Introduсtion

Socks5Systemz is a proxy botnet that appeared in 2016. Its main task is to turn your PC into a proxy server. The resulting proxies are sold or used for other purposes. The botnet made a lot of noise in the media, so I couldn't refuse to dig into it.

# Loader

They use a free Inno Setup written in delphi as the primary loader

![Die-InnoSetup](/posts_assets/socks5systemz/DIE_inno_setup.png)

I tried several unzipping programs, and they all required a password to unzip the file. But they allowed me to know the exact names of the files that were inside. With this information, I quickly dug up all the files using everything from the infected machine.

![Unpacked-Setup-Structure](/posts_assets/socks5systemz/Unpacked_Setup_Structure.png)

Along with the malware, a quite legitimate program volctl.exe was added to the installer.

My next step was to analyze the obtained binary. Inside there was approximately the following picture...

![Oh-fuck-protected](/posts_assets/socks5systemz/oh_fuck_protected.png)

The binary was covered with an unknown protector and did not want to start manually. I decided to look at the actions it performs in the system after installation. The most important was the creation of the SVGARateEX service, under which it was started after the system restart.

![Virus-Service](/posts_assets/socks5systemz/SVGARateEX_service.png)

# Main module

Next we had to find where the main functionality of the botnet was located, having seen that it sends some packets to the server after startup, I decided to put a break on all the functions that were somehow connected to the Internet.
The break worked in the rwx memory region allocated by the malware, so now I had to figure out where it was coming from. The most trivial thing to do was to attach the debugger right after the malware starts and put the break on VirtualAlloc, so that's what I did.

![Module-Mem-Alloc](/posts_assets/socks5systemz/module_mem_alloc.png)

After the break was triggered, I saw that it allocates a memory region with PAGE_EXECUTE_READWRITE permissions. After tracing this memory address I realized that it is the memory address where the module we need is loaded. What is interesting is that after the thread is created, the PE header is completely cleared.

![Module-load-func-call](/posts_assets/socks5systemz/module_load_func_call.png)

Now we had to find the place where data is written to the allocated buffer. Going to the first function after calling VirtualAlloc we can see the instruction rep movsd.

![Module-writing](/posts_assets/socks5systemz/module_writing.png)

The rep movsd instruction copies n number of bytes from the esi register to the edi register, at this moment the edi register contains the address of the previously allocated memory, and esi contains the module we need. Dump and we can continue analyzing.

Dumped module ready for analysis : [here](/posts_assets/socks5systemz/svgarateex_01785000.bin)

P.s If you do the dump manually, you will need to remove the 5 bytes of garbage that are before the MZ header

# Protector

![Dumped-module](/posts_assets/socks5systemz/DIE_dumped_module.png)

We can see that Oreans Code Virtualizer acts as a protector. The demo version was used in this case. It does not include virtualization macros and can only impose mutation on the code. It was a doubtful decision to cover binary with a protector, as it only increases the number of detections.

Ps. Voicemeeter.exe also used this protector, but the section name was changed, so DIE could not determine the name of the protector.

# Server communication

Once the module is fully initialized, it creates a main thread that starts sending packets to the server once a minute. Due to its large size, the function was not subject to mutation and I was able to easily analyze it statically.

![Packet-sending](/posts_assets/socks5systemz/Packet_sending.png)
The packet looks something like this and contains all the information about the infected client. Before sending, the packet is encrypted using rc4 and a static key
```i4hiea56#7b&dfw3```

```client_id=c1b0b3cc&connected=1&server_port=42522&debug=76&os=10.0.19044&dgt=1&dti=170163923```

In the response, the server sends one of 5 commands in encrypted form

![recevied-command](/posts_assets/socks5systemz/recv_command_processed.png)

```connect``` - connects to the ip specified in the packet and starts the proxy server (packets are sent via tcp)<br>
```disconnect``` - disconnects from the client and turns off the proxy server<br>
```idle``` - Waiting, the proxy server continues to operate<br>
```updips``` - updates the ip of the client to which the traffic is proxied<br>
```updurls``` - gets the url list and writes it to a file ```save.dat```

I tested it on a virtual machine for about an hour and after getting about 100k packets I never saw a packet with the updurls command, so it's not possible to say exactly what it's used for (all the small functions are in mutation). And the filename is not used anywhere else, so it's probably some unrealized feature.





