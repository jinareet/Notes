#Malloc_chunk
```
struct malloc_chunk{
    INTERNAL_SIZE_T prev_size;
    INTERNAL_SIZE_T size;

    struct malloc_chunk* fd;
    struct malloc_chunk* bk;

    struct malloc_chunk* fd_nextsize;
    struct malloc_chunk* bk_nextsize;
};
```
###INTERNAL_SIZE_T 

```
#ifndef INTERNAL_SIZE_T
#define INTERNAL_SIZE_T size_t
#endif
```
###SIZE_SZ

```
#define size_sz (sizeof(INTERNAL_SIZE_T)))
```
###MALLOC_ALIGN_MASK

```
#define MALLOC_ALIGN_MASK(MALLOC_ALIGNMENT - 1)
```

###chunk与mem指针转换  

    /*conversation from malloc headers to user pointers, and back */
    #define chunk2mem(p) ((void *)((char *)(p) +2 *SIZE_SZ))
    #define mem2chunk(mem) ((mchunkptr)((char *)(mem) - 2 *SIZE_SZ)

###最小chunk大小

    /* The smallest possible chunk */
    #define MIN_CHUNK_SIZE (offsetof(strict malloc_chunk, fd_nextsize))

```
/*The smallest size we can malloc is an aligned minimal chunk */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1 
#define MINSIZE \
    (unsigned long ) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) &  \
                       ~MALLOC_ALIGN_MASK))    
```
###检查是否对齐
**2 * SIZE_SZ大小对齐**

    /* Check if m has acceptable alignment */
    // MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
    #define aligned_OK(m) (((unsigned long) (m)& MALLOC_ALIGN_MASK) == 0)

    #define misaligned_chunk(p)\
        ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p))  \
         MALLOC_ALIGN_MASK)

###请求字节数判断

    /*
    Check if a request is so large that it would wrap around zero when
    padded and aligned. To simplify some other code, the bound is made
    low enough so that adding MINSIZE will also not wrap around zero.
    */

    #define REQUEST_OUT_OF_RANGE(req)                                              \
        ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))

###将用户请求内存大小转为实际分配内存大小
    /* pad request bytes into a usable size -- internal version */
    //MALLOC_ALIGN_MASK - 2 * SIZE_SZ -1
    #define request2size(req)                                   \
        (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)        \
         ? MINSIZE                                              \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

    #define checked_request2size(req, sz)       \
        if(REQUEST_OUT_OF_RANGE(req)){          \
        __set_errno(ENOMEM);                    \
        return 0;                               \
        }                                       \
        (sz) = request2size(req);

###Bin
对于small bins,l large bins, unsorted bins 来说，Ptmalloc 将它们维护在同一个数组中。这些bin对应的数据结构在malloc_state 中，如下

    #define NBINS 128
    /* Normal bins packed as described above */
    mchunkptr bins[NBINS * 2 -2];

+ 将每个bin(链表头)看作一个chunk，但只保留bk（指向最后一个可用chunk）, fd（指向第一个可用chunk）
####Fast Bins 
+ LIFO
+ Single-linked
+ 对应fastbinsY数组

####Small Bins
    
    公差为8或16，从下标2开始，到63; 共62个，大小由16B or 32B 到504B or 1008B
+ ```Chunk_size=2 * SIZE_SZ * index```


####Large Bins
+ Large bin中的chunk可能在两个链表中，（fd bk链表和fd_nextsize链表）

