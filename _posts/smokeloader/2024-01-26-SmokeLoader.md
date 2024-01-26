---
layout: post
title: "Diving into SmokeLoader shellcode"
date: 2024-01-25 19:00:01
tags : [malware,loader,windows]
---

# Sample

[Loader](https://bazaar.abuse.ch/sample/946583a0803167de24c7c0d768fe49546108e43500a1c2c838e7e0560addc818/)

# Introduction

Smoke Loader is a rather popular malware loader, the family of which appeared back in 2014. Its main technique is the use of some pretty interesting shellcodes.

# Shellcode loader

We open sample in ida and see a lot of random calls of functions from winapi. All such calls are just garbage that can be safely ignored. The only interesting thing here is the function that map shellcode into memory.

![main-function](/posts_assets/smokeloader/main_function.png)

The function allocates memory in the heap, changes protection to rwx and writes shellcode into it.

![shellcode-mapping](/posts_assets/smokeloader/mapping_shellcode.png)

After that, just calling shellcode

![calling-shellcode](/posts_assets/smokeloader/calling_shellcode.png)


# Shellcode analysis

I ran the resulting shellcode through several decompilers, Ida was the best at decompilation. The output is the following entry point.

![shellcode-entry](/posts_assets/smokeloader/shellcode_entry.png)

Having opened 1 function I immediately realized that it gets addresses of different winapi functions and puts them into some structure.

![shellcode-api-resolve](/posts_assets/smokeloader/shellcode_resolve_api_1.png)

The structure I have recreated looks something like this :

```cpp
struct ShellCode_Context
{
  int pad;
  int shellcode_2_size;
  int *shellcode_2_address;
  int i;
  unsigned int *LoadLibraryA;
  unsigned int *GetProcAddress;
  unsigned int *GlobalAlloc;
  unsigned int *GetLastError;
  unsigned int *Sleep;
  unsigned int *VirtualAlloc;
  unsigned int *CreateToolhelp32Snapshot;
  unsigned int *Module32First;
  unsigned int *CloseHandle;
};
```
We apply it to our pseudocode and get approximately this result. The hashing function here is quite simple, it uses the shl1_add algorithm.

![shellcode-api-resolve-2](/posts_assets/smokeloader/shellcode_resolve_api_2.png)

After receiving all addresses of all api functions, it tries to create a list of all modules of the process and checks if the first module is in the list. In general, I don't really understand why I need this piece of code, and I haven't found any information about it on the Internet.

![modules-list-getting](/posts_assets/smokeloader/modules_list_getting.png)

Initially I assumed that the following functions are needed to decrypt the packed binary and initialise it correctly. But it turned out that this shellcode is needed only to decrypt and start the second shellcode, which will do the main work.

![shellcode-2-initialization](/posts_assets/smokeloader/shellcode-2-map.png)

# Shellcode analysis 2

One of the features of the second shellcode, which immediately catches your eye, is its size, namely almost 500kb. It is almost 5 times bigger than the size of the first shellcode. The weight of the shellcode itself is not great about 3600 bytes, and right after it is a binary file that will be loaded into memory.

![binary-header](/posts_assets/smokeloader/binary_header.png)

As in the previous case at the very beginning he gets the addresses of the api functions he needs, the only difference is the lack of hashing.

![getting-kernel-address](/posts_assets/smokeloader/getting_kernel_address.png)

An interesting feature is that it does not try to access the fields of the structure directly, but folds the offsets of other fields to get the offset of the field it needs. This is an interesting solution that does not allow you to immediately understand which field it is trying to access (in static at least).

![iterating-on-export-directory](/posts_assets/smokeloader/iterating_on_export_directory.png)

At this point the most interesting part starts. It allocates a place in memory where it copies the binary that will be loaded into memory later. This location is temporary, because afterwards it uses VirtualProtect to change the protection on the base address of the shellcode loader. The protection change is necessary to completely clear its sections and write our malicious binary there.

![copy-binary-to-new-region](/posts_assets/smokeloader/copy_binary_to_new_region.png)

After the shellcode loader has been overwritten by our malware, it performs the standard actions of the Windows boot loader. Fix reloc addresses if the base address differs from the one in the PE header. Fixes the import table. All these pieces look very large in debugger, so I'll show only the import fix pseudocode (the code doesn't look very good).

![iat-table-fix](/posts_assets/smokeloader/iat_table_fix.png)

After successfully loading and preparing for execution, it calls the entry point





