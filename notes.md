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

## Install scudocookie library

`pip install scudocookie/dist/scudocookie-0.1-cp39-cp39-linux_x86_64.whl`

Example usage:

```
from scudocookie import bruteforce

cookie = bruteforce(addr, checksum, header)
```

# Build LLVM libc

[https://libc.llvm.org/full_host_build.html](https://libc.llvm.org/full_host_build.html) Reference tutorial from llvm website. Using build type Release since Debug caused linking to use too much memory (Windows with WSL). Make sure `$SYSROOT` is set for `cmake` and `ninja` commands to not mess up your system.

```
cd llvm-project  # The llvm-project checkout
mkdir build
cd build
SYSROOT=/path/to/sysroot

cmake ../llvm \
  -G Ninja \
  -DLLVM_ENABLE_PROJECTS="clang;libc;lld;compiler-rt" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DLLVM_LIBC_FULL_BUILD=ON \
  -DLLVM_LIBC_INCLUDE_SCUDO=ON \
  -DCOMPILER_RT_BUILD_SCUDO_STANDALONE_WITH_LLVM_LIBC=ON \
  -DCOMPILER_RT_BUILD_GWP_ASAN=OFF \
  -DCOMPILER_RT_SCUDO_STANDALONE_BUILD_SHARED=OFF \
  -DCLANG_DEFAULT_LINKER=lld \
  -DCLANG_DEFAULT_RTLIB=compiler-rt \
  -DDEFAULT_SYSROOT=$SYSROOT \
  -DCMAKE_INSTALL_PREFIX=$SYSROOT \
  -DLLVM_PARALLEL_LINK_JOBS=1
  
ninja install-clang install-builtins install-compiler-rt  \
   install-core-resource-headers install-libc install-lld
```

Then to build using the static linked LLVM libc (dynamic linking not available at the moment):

`$SYSROOT/bin/clang -static malloc-menu.c -o malloc-menu-libc`



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
 - Size check local cache? -> None, but size reset on allocation
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


## TransferBatch

Batch pointers
Count




- Overflow change class id
- Implement overflow



# Free primary as secondary

- Change class id and recalculate checksum
- Free it
- Block is added to cache
- If there were no allocated secondary blocks, breaks the inuselist (size overflow)
- Need to set CommitSize and CommitBase to be eligible for retrieval from cache


# Alloc stats

`perf stat -r 10 <command>`
`LD_PRELOAD=../malloc-menu-linux/libscudo-linux-fixed.so /usr/lib/linux-tools/5.15.0-89-generic/perf stat -r 10 ./benchmark`


## Repeated single block alloc/free

### unfixed older
```
 Performance counter stats for './single-block-used' (10 runs):

           5519.27 msec task-clock:u              #    1.002 CPUs utilized            ( +-  0.58% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000135      page-faults:u             #  181.739 K/sec                    ( +-  0.00% )
        4005672303      cycles:u                  #    0.728 GHz                      ( +-  7.28% )
         370446025      stalled-cycles-frontend:u #    7.31% frontend cycles idle     ( +- 71.63% )
         174243411      stalled-cycles-backend:u  #    3.44% backend cycles idle      ( +-  4.29% )
        3444492870      instructions:u            #    0.68  insn per cycle
                                                  #    0.39  stalled cycles per insn  ( +-  0.00% )
         748395384      branches:u                #  135.995 M/sec                    ( +-  0.00% )
          20565716      branch-misses:u           #    2.75% of all branches          ( +-  0.32% )

            5.5081 +- 0.0325 seconds time elapsed  ( +-  0.59% )
```

### unfixed latest
```
 Performance counter stats for './single-block-used' (10 runs):

           5896.21 msec task-clock:u              #    1.010 CPUs utilized            ( +-  0.47% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000133      page-faults:u             #  171.426 K/sec                    ( +-  0.00% )
        6996041786      cycles:u                  #    1.199 GHz                      ( +-  4.72% )
        2331966149      stalled-cycles-frontend:u #   39.84% frontend cycles idle     ( +- 14.08% )
         148940106      stalled-cycles-backend:u  #    2.54% backend cycles idle      ( +-  9.65% )
        4446545261      instructions:u            #    0.76  insn per cycle
                                                  #    0.26  stalled cycles per insn  ( +-  0.00% )
         937405794      branches:u                #  160.675 M/sec                    ( +-  0.00% )
          32364749      branch-misses:u           #    3.45% of all branches          ( +-  0.37% )

            5.8379 +- 0.0283 seconds time elapsed  ( +-  0.49% )
```

### fixed latest
```
 Performance counter stats for './single-block-used' (10 runs):

           5935.06 msec task-clock:u              #    1.020 CPUs utilized            ( +-  0.40% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000135      page-faults:u             #  172.050 K/sec                    ( +-  0.00% )
        7313517637      cycles:u                  #    1.258 GHz                      ( +-  4.23% )
        2411260930      stalled-cycles-frontend:u #   38.52% frontend cycles idle     ( +- 12.70% )
         241788734      stalled-cycles-backend:u  #    3.86% backend cycles idle      ( +-  4.85% )
        4620547666      instructions:u            #    0.74  insn per cycle
                                                  #    0.32  stalled cycles per insn  ( +-  0.00% )
         971405064      branches:u                #  167.108 M/sec                    ( +-  0.00% )
          33341124      branch-misses:u           #    3.43% of all branches          ( +-  0.84% )

            5.8170 +- 0.0230 seconds time elapsed  ( +-  0.39% )
```


## Repeated simultaneous 1000 blocks allocation then free

### unfixed older
```
 Performance counter stats for './many-blocks-used' (10 runs):

           6592.08 msec task-clock:u              #    0.997 CPUs utilized            ( +-  0.42% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000134      page-faults:u             #  152.185 K/sec                    ( +-  0.00% )
        5210360072      cycles:u                  #    0.793 GHz                      ( +-  0.35% )
        1222602996      stalled-cycles-frontend:u #   23.34% frontend cycles idle     ( +-  1.80% )
         502367048      stalled-cycles-backend:u  #    9.59% backend cycles idle      ( +-  4.14% )
        3467490377      instructions:u            #    0.66  insn per cycle
                                                  #    0.32  stalled cycles per insn  ( +-  0.00% )
         755395003      branches:u                #  114.945 M/sec                    ( +-  0.00% )
          20611457      branch-misses:u           #    2.73% of all branches          ( +-  0.95% )

            6.6130 +- 0.0351 seconds time elapsed  ( +-  0.53% )
```

### unfixed latest
```
 Performance counter stats for './many-blocks-used' (10 runs):

           7006.95 msec task-clock:u              #    0.987 CPUs utilized            ( +-  0.37% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000136      page-faults:u             #  141.913 K/sec                    ( +-  0.00% )
        6463628335      cycles:u                  #    0.917 GHz                      ( +-  0.44% )
        1552738627      stalled-cycles-frontend:u #   23.84% frontend cycles idle     ( +-  2.65% )
         341332890      stalled-cycles-backend:u  #    5.24% backend cycles idle      ( +-  6.80% )
        4469540499      instructions:u            #    0.69  insn per cycle
                                                  #    0.37  stalled cycles per insn  ( +-  0.00% )
         944403124      branches:u                #  134.005 M/sec                    ( +-  0.00% )
          31714971      branch-misses:u           #    3.36% of all branches          ( +-  0.95% )

            7.0976 +- 0.0370 seconds time elapsed  ( +-  0.52% )
```

### fixed latest
```
 Performance counter stats for './many-blocks-used' (10 runs):

           9577.59 msec task-clock:u              #    0.973 CPUs utilized            ( +-  0.42% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000138      page-faults:u             #  102.972 K/sec                    ( +-  0.00% )
       15694047853      cycles:u                  #    1.616 GHz                      ( +-  0.18% )
        2013605657      stalled-cycles-frontend:u #   12.75% frontend cycles idle     ( +-  1.13% )
        2639314014      stalled-cycles-backend:u  #   16.71% backend cycles idle      ( +-  1.04% )
       18130045944      instructions:u            #    1.15  insn per cycle
                                                  #    0.15  stalled cycles per insn  ( +-  0.00% )
        4974405509      branches:u                #  512.155 M/sec                    ( +-  0.00% )
          34019939      branch-misses:u           #    0.68% of all branches          ( +-  0.17% )

            9.8458 +- 0.0576 seconds time elapsed  ( +-  0.58% )
```


## Repeated random allocations/frees of 1000 blocks

### unfixed older
```
 Performance counter stats for './random-blocks-order' (10 runs):

           3780.25 msec task-clock:u              #    1.037 CPUs utilized            ( +-  0.77% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
            500393      page-faults:u             #  137.319 K/sec                    ( +-  0.00% )
        2546433313      cycles:u                  #    0.699 GHz                      ( +-  0.59% )
         397333219      stalled-cycles-frontend:u #   16.29% frontend cycles idle     ( +-  1.56% )
         159282904      stalled-cycles-backend:u  #    6.53% backend cycles idle      ( +-  1.11% )
        1821884390      instructions:u            #    0.75  insn per cycle
                                                  #    0.20  stalled cycles per insn  ( +-  0.00% )
         397301382      branches:u                #  109.029 M/sec                    ( +-  0.00% )
          11676013      branch-misses:u           #    2.94% of all branches          ( +-  0.74% )

            3.6467 +- 0.0291 seconds time elapsed  ( +-  0.80% )
```

### unfixed latest
```
 Performance counter stats for './random-blocks-order' (10 runs):

           3746.38 msec task-clock:u              #    0.981 CPUs utilized            ( +-  1.11% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
            500390      page-faults:u             #  131.081 K/sec                    ( +-  0.00% )
        2942292104      cycles:u                  #    0.771 GHz                      ( +-  0.76% )
         347599996      stalled-cycles-frontend:u #   11.68% frontend cycles idle     ( +-  3.72% )
         154891521      stalled-cycles-backend:u  #    5.20% backend cycles idle      ( +-  1.60% )
        2323080650      instructions:u            #    0.78  insn per cycle
                                                  #    0.16  stalled cycles per insn  ( +-  0.00% )
         491829748      branches:u                #  128.838 M/sec                    ( +-  0.00% )
          16904146      branch-misses:u           #    3.44% of all branches          ( +-  0.35% )

            3.8206 +- 0.0418 seconds time elapsed  ( +-  1.10% )
```

### fixed latest
```
 Performance counter stats for './random-blocks-order' (10 runs):

           4351.99 msec task-clock:u              #    0.993 CPUs utilized            ( +-  0.11% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
            500387      page-faults:u             #  114.279 K/sec                    ( +-  0.00% )
        5312778609      cycles:u                  #    1.213 GHz                      ( +-  0.10% )
         499379584      stalled-cycles-frontend:u #    9.37% frontend cycles idle     ( +-  0.86% )
         693098213      stalled-cycles-backend:u  #   13.00% backend cycles idle      ( +-  0.34% )
        5808080261      instructions:u            #    1.09  insn per cycle
                                                  #    0.12  stalled cycles per insn  ( +-  0.02% )
        1515662907      branches:u                #  346.149 M/sec                    ( +-  0.02% )
          18073170      branch-misses:u           #    1.19% of all branches          ( +-  0.38% )

           4.38057 +- 0.00496 seconds time elapsed  ( +-  0.11% )
```


## Repeated random allocations/frees of 1000 blocks, 500 blocks initially allocated

### unfixed older
```
 Performance counter stats for './random-half-blocks-order' (10 runs):

           3640.64 msec task-clock:u              #    1.005 CPUs utilized            ( +-  0.34% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
            500683      page-faults:u             #  138.339 K/sec                    ( +-  0.00% )
        2416742218      cycles:u                  #    0.668 GHz                      ( +-  0.42% )
         345321983      stalled-cycles-frontend:u #   14.22% frontend cycles idle     ( +-  2.87% )
         151300424      stalled-cycles-backend:u  #    6.23% backend cycles idle      ( +-  1.42% )
        1822807550      instructions:u            #    0.75  insn per cycle
                                                  #    0.20  stalled cycles per insn  ( +-  0.00% )
         397503577      branches:u                #  109.831 M/sec                    ( +-  0.00% )
          11350331      branch-misses:u           #    2.86% of all branches          ( +-  0.44% )

            3.6220 +- 0.0122 seconds time elapsed  ( +-  0.34% )
```

### unfixed latest
```
 Performance counter stats for './random-half-blocks-order' (10 runs):

           3735.29 msec task-clock:u              #    0.993 CPUs utilized            ( +-  0.37% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
            500678      page-faults:u             #  133.260 K/sec                    ( +-  0.00% )
        2952084437      cycles:u                  #    0.786 GHz                      ( +-  0.32% )
         377885874      stalled-cycles-frontend:u #   12.85% frontend cycles idle     ( +-  1.59% )
         114284279      stalled-cycles-backend:u  #    3.88% backend cycles idle      ( +-  3.77% )
        2324278878      instructions:u            #    0.79  insn per cycle
                                                  #    0.15  stalled cycles per insn  ( +-  0.00% )
         492083591      branches:u                #  130.972 M/sec                    ( +-  0.00% )
          16998050      branch-misses:u           #    3.45% of all branches          ( +-  0.26% )

            3.7602 +- 0.0142 seconds time elapsed  ( +-  0.38% )
```

### fixed latest
```
 Performance counter stats for './random-half-blocks-order' (10 runs):

           4606.58 msec task-clock:u              #    1.001 CPUs utilized            ( +-  0.47% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
            500691      page-faults:u             #  108.896 K/sec                    ( +-  0.00% )
        6033179258      cycles:u                  #    1.312 GHz                      ( +-  0.21% )
         498366294      stalled-cycles-frontend:u #    8.30% frontend cycles idle     ( +-  1.72% )
         894513131      stalled-cycles-backend:u  #   14.89% backend cycles idle      ( +-  0.27% )
        6832879007      instructions:u            #    1.14  insn per cycle
                                                  #    0.13  stalled cycles per insn  ( +-  0.02% )
        1819209128      branches:u                #  395.661 M/sec                    ( +-  0.02% )
          18405741      branch-misses:u           #    1.01% of all branches          ( +-  0.35% )

            4.5997 +- 0.0214 seconds time elapsed  ( +-  0.47% )
```

## Repeated simultaneous 10000 blocks allocation then free

### unfixed older
```
 Performance counter stats for './many-many-blocks-used' (10 runs):

           7001.24 msec task-clock:u              #    1.001 CPUs utilized            ( +-  0.27% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000155      page-faults:u             #  143.407 K/sec                    ( +-  0.00% )
        5815205287      cycles:u                  #    0.834 GHz                      ( +-  0.31% )
        1134412966      stalled-cycles-frontend:u #   19.73% frontend cycles idle     ( +-  5.97% )
        1257998821      stalled-cycles-backend:u  #   21.88% backend cycles idle      ( +-  5.64% )
        3467495409      instructions:u            #    0.60  insn per cycle
                                                  #    0.36  stalled cycles per insn  ( +-  0.00% )
         755395762      branches:u                #  108.312 M/sec                    ( +-  0.00% )
          20384924      branch-misses:u           #    2.70% of all branches          ( +-  0.14% )

            6.9967 +- 0.0189 seconds time elapsed  ( +-  0.27% )
```


### unfixed latest
```
 Performance counter stats for './many-many-blocks-used' (10 runs):

           6617.37 msec task-clock:u              #    1.023 CPUs utilized            ( +-  0.94% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000148      page-faults:u             #  154.935 K/sec                    ( +-  0.00% )
        3334896542      cycles:u                  #    0.517 GHz                      ( +-  0.74% )
         897693806      stalled-cycles-frontend:u #   27.63% frontend cycles idle     ( +-  1.79% )
        1424963167      stalled-cycles-backend:u  #   43.86% backend cycles idle      ( +-  1.24% )
         697328732      instructions:u            #    0.21  insn per cycle
                                                  #    2.10  stalled cycles per insn  ( +-  0.00% )
         139371974      branches:u                #   21.590 M/sec                    ( +-  0.00% )
          16246519      branch-misses:u           #   11.66% of all branches          ( +-  0.17% )

            6.4697 +- 0.0645 seconds time elapsed  ( +-  1.00% )
```

### fixed latest
```
 Performance counter stats for './many-many-blocks-used' (10 runs):

          10329.68 msec task-clock:u              #    1.089 CPUs utilized            ( +-  1.22% )
                 0      context-switches:u        #    0.000 /sec
                 0      cpu-migrations:u          #    0.000 /sec
           1000179      page-faults:u             #  106.730 K/sec                    ( +-  0.00% )
       14936055595      cycles:u                  #    1.594 GHz                      ( +-  0.54% )
        1229385524      stalled-cycles-frontend:u #    8.58% frontend cycles idle     ( +-  0.84% )
        2041390053      stalled-cycles-backend:u  #   14.25% backend cycles idle      ( +-  2.24% )
       26805634958      instructions:u            #    1.87  insn per cycle
                                                  #    0.08  stalled cycles per insn  ( +-  0.00% )
       12149575435      branches:u                #    1.296 G/sec                    ( +-  0.00% )
          30090624      branch-misses:u           #    0.25% of all branches          ( +-  0.73% )

             9.487 +- 0.130 seconds time elapsed  ( +-  1.37% )
```


## mimalloc-bench

```
#------------------------------------------------------------------
# test         alloc       time    rss    user  sys  page-faults page-reclaims
cfrac          scudo       08.82   4632   8.59  0.05 0           614
cfrac          scudo_fixed 08.52   4644   8.43  0.03 0           618
espresso       scudo       05.37   4704   5.27  0.03 0           640
espresso       scudo_fixed 05.44   4708   5.39  0.05 0           643
barnes         scudo       03.03   62200  2.90  0.06 0           4329
barnes         scudo_fixed 03.25   63364  3.19  0.01 0           2901
redis          scudo       5.159   9660   0.19  0.04 0           1474
redis          scudo_fixed 4.820   9684   0.22  0.01 0           1481
larsonN-sized  scudo       82.708  14688  5.51  0.14 6           2521
larsonN-sized  scudo_fixed 67.638  15396  8.41  0.18 0           2692
mstressN       scudo       00.14   12008  0.07  0.04 1           27306
mstressN       scudo_fixed 00.13   12028  0.07  0.03 0           27410
rptestN        scudo       2.211   23092  0.36  0.40 3           59795
rptestN        scudo_fixed 1.522   16392  0.25  0.38 0           59246
gs             scudo       01.38   40072  1.18  0.04 252         29345
gs             scudo_fixed 01.26   40152  1.13  0.07 0           29696
lua            scudo       05.85   71428  4.75  0.46 926         178671
lua            scudo_fixed 05.38   71848  4.76  0.40 0           179362
alloc-test1    scudo       04.82   15660  4.67  0.02 2           3011
alloc-test1    scudo_fixed 04.89   15712  4.68  0.03 0           3013
alloc-testN    scudo       05.42   15236  9.40  0.05 0           3757
alloc-testN    scudo_fixed 05.34   15148  9.38  0.06 0           3937
sh6benchN      scudo       06.67   478560 10.67 0.70 1           134372
sh6benchN      scudo_fixed 06.58   478860 10.84 0.51 0           135097
sh8benchN      scudo       43.33   151272 67.93 3.43 1           293981
sh8benchN      scudo_fixed 41.48   151816 66.44 3.05 0           298107
xmalloc-test   scudo       10.060  48904  7.78  0.34 3           25004
xmalloc-testN  scudo_fixed 9.826   49136  7.78  0.33 0           28887
cache-scratch1 scudo       01.40   4016   1.32  0.00 1           253
cache-scratch1 scudo_fixed 01.33   3832   1.28  0.00 0           249
cache-scratchN scudo       00.79   3944   1.40  0.00 0           254
cache-scratchN scudo_fixed 00.76   3924   1.32  0.01 0           256
glibc-simple   scudo       04.57   3472   4.38  0.02 1           331
glibc-simple   scudo_fixed 03.76   3720   3.68  0.01 0           335
glibc-thread   scudo       14.607  3932   3.49  0.01 1           401
glibc-thread   scudo_fixed 14.650  3964   3.51  0.00 0           401
```
