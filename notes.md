# Hooks

- `__scudo_allocate_hook(void* TaggedPointer, uptr Size)`
- `__scudo_deallocate_hook(void* Pointer)`


# Random stuff to check

- Memory tagging


# Checksum

Checksum is 16 bits, Cookie is 32 bits
header is 64 bits, split into parts of 32 bit -> 2 parts

Crc = crc32(crc32(crc32(Cookie, chunk ptr), first half of header), second half of header)
checksum is Crc ^ (Crc >> 16) = lower 16 bits xor higher 16 bits

Header is:

ClassID:            8 bits
State:              2 bits
Origin:             2 bits
SizeOrUnusedBytes: 20 bits
Offset:            16 bits
Checksum:          16 bits

Offset is generally 0, checksum is set to 0 for calculation of the checksum.
If we have one allocation, we know the size, we might know the origin depending on context, state has to be allocated, and ClassId can be calculated from the size based on the configuration. So the only things we don't know are the chunk ptr and cookie, but there is a good chance we know the ptr address too. Therefore if we have one checksum leak, we can bruteforce the cookie since it's only 32 bits, and crc32 is pretty fast. (At least in C, need to find a way to do it in Python still)

for compareAndExchangeHeader checksum is not 0 in the header!

# Deallocate

Checks:
 - Alignment
 - Header Checksum
 - Allocation State
 - (if enabled) Allocation Type
   - If Memalign origin in header or deallocate called from malloc (free) passes anyway
 - (if enabled) Delete size
 - Header race during state change (uninteresting)
 - (Primary) ClassId less than NumClasses (uint64 comparison)

Notes:
 - Checksum is recalculated when state changes

# Allocate

Checks:
 - Alignment
 - Allocation Size not too big
 - header not checked before retrieving from cache

Notes:
 - Checksum is computed based on previous checksum
 - Is offset reset?
 
