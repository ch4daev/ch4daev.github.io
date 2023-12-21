---
layout: post
title: "Socks5Systemz"
date: 2023-12-18 18:20:11
categories: malware botnet windows
---

Loader : [Malware Bazaare](https://bazaar.abuse.ch/sample/22fdfde16d444cb9abe26e5f06cc4d7b72b98499a3819240615fef58cf6b41e5/)

Unpacked files : [Unpac.me](https://www.unpac.me/results/0bb17dae-7192-42df-aa90-c14215b1a661?hash=d380580f5ee79d082f97c198ffc5185abefcc539a1e49f94ae208589605aaba1#/)

Dumped module : [dump here](svgarateex_01785000.bin)

# Introduсtion

Socks5Systemz is a proxy botnet that appeared in 2016. Its main task is to turn your PC into a proxy server. The resulting proxies are sold or used for other purposes. The botnet made a lot of noise in the media, so I couldn't refuse to dig into it.

# Loader

They use a free Inno Setup written in delphi as the primary loader

![Die-InnoSetup](/posts_assets/socks5systemz/DIE_inno_setup.png)

I tried several unzipping programs, and they all required a password to unzip the file. But they allowed me to find out the exact names of the files inside. With this information, I quickly dug up all the files using everything from the infected machine.

![Unpacked-Setup-Structure](/posts_assets/socks5systemz/Unpacked_Setup_Structure.png)

What's interesting is that in addition to the malicious Voicemeeter.exe, it installs a clean Japanese program volctl.exe to control the sound.

My next step was to analyze the received binary. Inside there was a picture like this...

![Oh-fuck-protected](/posts_assets/socks5systemz/oh_fuck_protected.png)

I didn't get too upset and went to analyze it in dynamics.

After starting it up, it renamed itself SVGARateEX.exe, and created the "SVGARateEX" service to save itself to the system.

![Virus-Service](/posts_assets/socks5systemz//SVGARateEX_service.png)

It will take me a long time to tell you how I analyzed the protected Voicemeeter.exe, but eventually I found the memory location where the module responsible for the main botnet functionality was located.

Dumped module ready for analysis : [here](/posts_assets/socks5systemz/svgarateex_01785000.bin)

![Dumped-module](/posts_assets/socks5systemz/DIE_dumped_module.png)

We can see that Oreans Code Virtualizer acts as a protector. The demo version was used in this case. It does not include virtualization macros and can only impose mutation on the code.

Ps. Voicemeeter.exe also used this protector, but the section name was changed, so DIE could not determine the name of the protector.

# Server communication

Once the module is fully initialized, it creates a main thread that starts sending packets to the server once a minute.

![Packet-sending](/posts_assets/socks5systemz/Packet_sending.png)

The packet looks something like this and contains all the information about the infected client. Before sending, the packet is encrypted using rc4 and the static key ``i4hiea56#7b&dfw3``

```client_id=c1b0b3cc&connected=1&server_port=42522&debug=76&os=10.0.19044&dgt=1&dti=170163923```

In the response, the server sends one of 5 commands in encrypted form

![recevied-command](/posts_assets/socks5systemz/recv_command_processed.png)

```connect``` - connects to the ip specified in the packet and starts the proxy server (packets are sent via tcp)<br>
```disconnect``` - disconnects from the client and turns off the proxy server<br>
```idle``` - Waiting, the proxy server continues to operate<br>
```updips``` - updates the ip of the client to which the traffic is proxied<br>
```updurls``` - gets the url list and writes it to a file ```save.dat```

I tested it on a virtual machine for about an hour and after getting about 100k packets I never saw a packet with the updurls command, so it's not possible to say exactly what it's used for (all the small functions are in mutation). And the filename is not used anywhere else, so it's probably some unrealized feature.



# End

The article is not very big, and there is not much to tell. The most time was spent on finding the module, initially I didn't understand where it was loaded into memory from, because Ida just didn't convert this piece of code into a function. A questionable solution was to cover the binary with a protector, after I covered a clean binary with the same protector, the total number of detections increased from 6 to 17.





