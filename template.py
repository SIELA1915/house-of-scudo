#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("../scudo-gdb-tooling/malloc-menu-linux")

gs = '''
continue
'''

env = {"LD_PRELOAD": "/home/siela1915/BA_Project/libscudo.so"}

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, env=env)
    else:
        return process(elf.path, env=env, stdin=PTY)

# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send(b"1\n")
    io.sendafter(b"allocate: ", f"{size}\n".encode())
    chunk = io.recvline()
    index = chunk.split(b' ')[4]
    address = int(chunk.split(b' ')[7], 16)
    io.sendafter(b"quit\n", b"3\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", hex(address))
    io.send(b"\n")
    io.sendafter(b"write: ", f"{len(data)}\n".encode())
    io.sendafter(b"write: ", data)
    io.send(b"\n")
    return (index, address)

# Send the "free" option, send the address
def free(address):
    io.send(b"2\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", hex(address))
    io.send(b"\n")

def write(address, data):
    io.send(b"3\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", hex(address))
    io.send(b"\n")
    io.sendafter(b"write: ", f"{len(data)}\n".encode())
    io.sendafter(b"write: ", data)
    io.send(b"\n")
    
io = start()


# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# The malloc() function chooses option 1 and then 3 from the menu.
# Its arguments are "size" and "data".
ind1, add1 = malloc(24, b"Y"*24)
ind2, add2 = malloc(24, b"X"*24)

write(add1, b"X"*12)
write(add2, b"Y"*12)

free(add1)
free(add2)

# =============================================================================

io.interactive()
