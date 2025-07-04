#pragma once

#include <stddef.h>


// Configurable constants - start

// Must be a multiple of sizeof(size_t).
#define HEAP_SIZE 4294967296

// Must be a multiple of sizeof(size_t) and at least
// (sizeof(free_node_t) - sizeof(header_node_t)).
#define MIN_ALLOC_SIZE (sizeof(free_node_t) - sizeof(header_node_t))

// Must be at least sizeof(free_node_t).
// When shrinking with realloc, if a new free node would be created instead of
// merging with another free node, a new free node will only be created if its
// size would be at least this constant; otherwise, the allocation will not
// shrink. This reduces the number of small nodes that are inserted at the
// start of the free list.
#define MIN_SHRINK_SPLIT_SIZE (sizeof(free_node_t) * 4)

// Configurable constants - end


#define SIZE_T_MAX ((size_t) -1)

// Bitmasks to determine/ignore MSB of size_t and check alignment.
#if (SIZE_T_MAX == 0xFFFF)
    #define SIZE_T_MSB_MASK 0x8000
    #define SIZE_T_REST_MASK 0x7FFF
    #define POINTER_ALIGHMENT_MASK 0x1
#elif (SIZE_T_MAX == 0xFFFFFFFF)
    #define SIZE_T_MSB_MASK 0x80000000
    #define SIZE_T_REST_MASK 0x7FFFFFFF
    #define POINTER_ALIGHMENT_MASK 0x3
#elif (SIZE_T_MAX == 0xFFFFFFFFFFFFFFFF)
    #define SIZE_T_MSB_MASK 0x8000000000000000
    #define SIZE_T_REST_MASK 0x7FFFFFFFFFFFFFFF
    #define POINTER_ALIGHMENT_MASK 0x7
#else
    #error Could not determine bitmasks for size_t.\
    sizeof(size_t) was expected to be 2, 4, or 8.
#endif


typedef struct header_node_t {
    // The header list: doubly-linked list of contiguous free and allocated
    // nodes.
    // The next node pointer can be calculated as follows:
    // current_node + sizeof(header_node_t) + size.
    // This calculation applies to both free and allocated nodes because size
    // excludes free_node_t.header but includes the rest of free_node_t.
    struct header_node_t *prev;

    // Size usable by the caller. This field excludes the size of this struct
    // but includes the remaining size of free_node_t if this node is free.
    // MSB = 0 iff allocated; MSB = 1 iff free.
    size_t size;
} header_node_t;

// Note: free_node_t MUST begin with a header_node_t so that free_node_t and
// header_node_t can be converted to each other without needing to move any
// header data.
typedef struct free_node_t {
    header_node_t header;

    // The free list: doubly-linked list of potentially not contiguous free
    // nodes.
    struct free_node_t *next_free;
    struct free_node_t *prev_free;
} free_node_t;
