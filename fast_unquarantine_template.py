#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("../scudo-gdb-tooling/malloc-menu-linux")

gs = '''
continue
'''

env = {"LD_PRELOAD": "/home/siela1915/BA_Project/libscudo.so"}

if args.NOSCUDO:
    env = {}
elif args.QUARANTINE:
    env["SCUDO_OPTIONS"] = ":".join([
        "thread_local_quarantine_size_kb=5",
        "quarantine_size_kb=10",
        "quarantine_max_chunk_size=2048",
        "release_to_os_interval_ms=-1"
    ])

    
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, env=env)
    else:
        return process(elf.path, env=env, stdin=PTY)

# Select the "malloc" option, send size & data.
def malloc(size, data=None):
    io.send(b"1\n")
    io.sendafter(b"allocate: ", f"{size}\n".encode())
    chunk = io.recvline()
    index = chunk.split(b' ')[4]
    address = int(chunk.split(b' ')[7], 16)
    if data:
        io.sendafter(b"quit\n", b"3\n")
        io.sendafter(b"address: ", b"2\n")
        io.sendafter(b"address: ", f"{hex(address)}\n".encode())
        io.sendafter(b"write: ", f"{len(data)}\n".encode())
        io.sendafter(b"write: ", data)
        io.send(b"\n")
    return (index, address)

# Send the "free" option, send the address
def free(address):
    io.send(b"2\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", f"{hex(address)}\n".encode())

def write(address, data):
    io.send(b"3\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", f"{hex(address)}\n".encode())
    io.sendafter(b"write: ", f"{len(data)}\n".encode())
    io.sendafter(b"write: ", data)
    io.send(b"\n")

def populate_quarantine():
    for i in range(200):
        free(malloc(0x20+i)[1])
    
io = start()


# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# The malloc() function chooses option 1 and then 3 from the menu.
# Its arguments are "size" and "data".
ind1, add1 = malloc(16, b"a"*16)

info(f"First address: {hex(add1)}")

free(add1)

ind2, add2 = malloc(16, b"b"*16)

info(f"Second address after first free: {hex(add2)}")

populate_quarantine()

ind3, add3 = malloc(16, b"c"*16)

info(f"Third address after populate: {hex(add3)}")

# =============================================================================

io.interactive()
