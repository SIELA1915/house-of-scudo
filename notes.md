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
 - Size check local cache? -> None!!!
 - ClassId 0 -> treated like secondary

# Allocate

Checks:
 - Alignment
 - Allocation Size not too big
 - Rss Limit
 
 - header not checked before retrieving from cache

Notes:
 - Is offset reset?
 
# Refill local cache

Popped TransferBatch count > 0
Chunks array of TransferBatch copied to PerClass
Count of popped TransferBatch set to 0
TransferBatch deallocated

# Drain local cache

Pushes first half of cache to TransferBatches
Copies second half of cache to first half -> if corrupt localcache count twice same chunk


Secondary
Free List


# Secondary Blocks

## Allocate

- Alignment
- Max Size

### Found in cache

- Fill content if asked
- Add to in use blocks

-> continue with normal header allocation

### Not found in cache

MapSize = size + 2 guard pages
map MapSize with `MAP_NOACCESS | MAP_ALLOWNOMEM`
Set CommitBase to MapBase + 1 page

If Alignment >= PageSize and 32 bit:
- Trim map begin and end

CommitSize = MapEnd - PageSize - CommitBase
AllocPos = CommitBase + CommitSize - Size, rounded down to Alignmentt

map secondary at CommitBase for CommitSize with `MAP_RESIZABLE`

HeaderPos = AllocPos - normal header size - largeblock header size

Add tag to header if memory tagging enabled

Fill large block header with values

add to InUseBlocks (sets prev and next pointers)


## Deallocate

Remove from InUseBlocks (sets prev->next to next and next->prev to prev and first/last if needed)
 - Checks if prev->next was cur and next->prev was cur

Store in cache

## Cache

### Retrieve

Iterate over all entries:

- AllocPos = CommitBase + CommitSize - Size, round down to alignment
- HeaderPos = AllocPos - normal chunk header size - large block header size
- Check HeaderPos no overflow (> CommitBase + CommitSize)
- HeaderPos insite Committed size, doesn't leave more than MaxUnusedCachePages unused in committed space

If found:

- If memory tagging:
  - Add tag to pointer
  - Add stuff for zeroing
- Add to InUseBlocks (sets next and prev pointers)


### Store

if size too big -> unmap
else:

- Fill cached block entry with header values,
- If ReleaseToOSIntervalMs is 0, release pages and set Time to 0
  - else set time
- If 4 full events -> empty cache
- Move first cache entry to first unused entry
- Put current block into first spot in list
- Release old entries
- If no spot in cache found for current block, unmap it




# Freelist

## BatchGroup

Pointer to next BatchGroup
Group Id
Max Cached per Transfer Batch
Num Pushed Blocks
Pushed Blocks at Last Checkpoint
Linked List of TransferBatches

### Corrupted

if Cur->GroupId < ptrGroup Array[I] and Cur->Next->GroupId == ptrGroup Array[I]
 -> first transferbatch count < maxcached per transfer batch
 -> memcpy(Batch + Count, Array, sizeof(batch)*N)

### New BatchGroup created

- all fields are reset :(

## Add blocks to freelist

- If blocks are from batch class id, create batchgroup and transferbatches in the provided blocks
- Add to BatchGroup depending on group (based on address)
  - Iterates over BatchGroup list -> can corrupt


