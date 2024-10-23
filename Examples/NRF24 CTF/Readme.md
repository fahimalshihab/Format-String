# Writeup
## Challenge Name : New Start
It was a pretty basic buffer overflow challenge.

- Lets checksec the file first.

![image](https://github.com/user-attachments/assets/bbd3daa9-c779-4335-8209-30b9f39d6d64)

We have PIE enabled here PIE stands for Position Independent Executable,
which means that every time you run the file it gets loaded into a different memory address. 
This means you cannot hardcode values such as function addresses and gadget locations without finding out where they are.

After running the file sevarel time we got some leaks and everytime its different so you know now why these are different .
![Screenshot from 2024-10-23 21-34-20](https://github.com/user-attachments/assets/1730cf7f-3ab9-4c9c-845a-fe2bf4ec1b10)


### Analysis
Luckily, this does not mean it's impossible to exploit. PIE executables are based around relative rather than absolute addresses, meaning that while the locations in memory are fairly random the offsets between different parts of the binary remain constant. For example, if you know that the function main is located 0x128 bytes in memory after the base address of the binary, and you somehow find the location of main, you can simply subtract 0x128 from this to get the base address and from the addresses of everything else.

First thing first Lets check in ghydra :
![image](https://github.com/user-attachments/assets/87eb574d-a0a7-44b7-8167-e73c87d1c7a3)

Its a Buffer Overflow Vulnerability Lets see :

## Overview

The buffer overflow vulnerability in the provided C code snippet arises from the use of the `gets` function, which does not perform any bounds checking on user input. Let's analyze this in detail.

## Code Context

The relevant part of the code is:

```c
char local_28[32];
gets(local_28);
```
## Explanation of Buffer Overflow

### Buffer Definition

- `local_28` is defined as an array of 32 characters. This means it can store up to 31 characters plus a null terminator (`\0`).

### Use of `gets` Function

- The `gets` function reads a line of input from standard input (stdin) and stores it in the buffer `local_28`.

- **Critical Flaw**: `gets` does not check the length of the input. If a user inputs more than 31 characters, it will overflow the buffer.
