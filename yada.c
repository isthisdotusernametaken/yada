#include "yada_heap.h"

#include <pthread.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#include <string.h>
#include <sys/mman.h>


// Set the local variable size_t byte_size = nmemb * size iff it will not
// overflow; otherwise, set errno to ENOMEM and return NULL.
#define CALCULATE_ARRAY_SIZE_CHECKED \
    size_t byte_size = nmemb * size; \
    if (size != 0 && byte_size / size != nmemb) { \
        errno = ENOMEM; \
        return NULL; \
    }

#define LOCK pthread_mutex_lock(&_heap_lock)
#define UNLOCK pthread_mutex_unlock(&_heap_lock)


// Dummy head of heap
free_node_t *free_list = NULL;

// Lock for all heap operations
pthread_mutex_t _heap_lock = PTHREAD_MUTEX_INITIALIZER;


// Return the start of the next header_node_t, or NULL iff current is the last
// node in the heap.
static inline header_node_t *get_next_node(
    header_node_t *current, size_t size) {

    void *next = (void *) current + sizeof(header_node_t) + size;

    return next < (void *) free_list + HEAP_SIZE ? next : NULL;
}

// Return the start of the next header_node_t, or NULL iff current is the last
// node in the heap.
static inline header_node_t *get_next_node_f(free_node_t *current) {
    return get_next_node((header_node_t *) current, current->header.size);
}

// Return the start of the memory usable by the client in the given node.
static inline void *get_usable_memory(header_node_t *node) {
    return (void *) node + sizeof(header_node_t);
}

// Return the header of the node whose usable memory is provided.
static inline header_node_t *get_node(void *usable_memory_start) {
    return usable_memory_start - sizeof(header_node_t);
}

static inline size_t get_allocated_size(header_node_t *node) {
    return node->size & SIZE_T_REST_MASK;
}

// Change the prev pointer of the node immediately after current to point to
// new_prev instead of current.
// This can either remove current and possibly additional earlier nodes from
// the header list by bypassing those nodes (to merge new_prev with some number
// of contiguous previous nodes) or insert a new node immediately after current
// (to split current into two nodes).
static inline void set_next_prev(
    free_node_t *current, header_node_t *new_next_prev) {

    header_node_t *next = get_next_node_f(current);
    if (next)
        next->prev = new_next_prev;
}

static inline size_t is_allocated(header_node_t *node) {
    return node->size & SIZE_T_MSB_MASK;
}

// Remove old from the free list, and insert replacement in old's position.
// The fields of each free_node_t are reassigned in an order such that, if
// replacement is AFTER old in memory, replacement may partially overlap with
// old without issue. replacement may be as early as
// (void *) old + sizeof(size_t).
static inline void replace_in_free_list(
    free_node_t *old, free_node_t *replacement) {

    if (old->next_free)
        old->next_free->prev_free = replacement;
    old->prev_free->next_free = replacement;
    replacement->prev_free = old->prev_free;
    replacement->next_free = old->next_free;
}

// Remove old from the free list, and insert replacement in old's position.
// The fields of each free_node_t are reassigned in an order such that, if
// replacement is BEFORE old in memory, replacement may partially overlap with
// old without issue. old may be as early as
// (void *) replacement + sizeof(size_t).
static inline void replace_in_free_list_before(
    free_node_t *old, free_node_t *replacement) {

    if (old->next_free)
        old->next_free->prev_free = replacement;
    old->prev_free->next_free = replacement;
    replacement->next_free = old->next_free;
    replacement->prev_free = old->prev_free;
}

// Remove to_remove from the free list.
static inline void remove_from_free_list(free_node_t *to_remove) {
    free_node_t *prev = to_remove->prev_free;
    prev->next_free = to_remove->next_free;
    if (to_remove->next_free)
        to_remove->next_free->prev_free = prev;
}

// Insert new_free after prev in the free list.
static inline void insert_in_free_list(
    free_node_t *prev, free_node_t *new_free) {

    new_free->next_free = prev->next_free;
    if (prev->next_free)
        prev->next_free->prev_free = new_free;
    prev->next_free = new_free;
    new_free->prev_free = prev;
}

// Determine whether ptr is too early or late in memory to possibly refer to a
// valid pointer returned by this allocator (i.e., before the start of the
// first node's usable space or after the start of the last potential node's
// usable space). This also accounts for null pointers.
// Pointers that pass this test are suitable for free and realloc, but
// not using pointers that fail this test does not prevent heap corruption by
// providing invalid pointers within the checked bounds.
static inline int allocation_out_of_heap_range(void *ptr) {
    return
        (ptr <
            (void *) free_list + sizeof(free_node_t) + sizeof(header_node_t)) |
        (ptr > (void *) free_list + HEAP_SIZE - MIN_ALLOC_SIZE);
}

static inline size_t is_unaligned(void *ptr) {
    return (size_t) ptr & POINTER_ALIGHMENT_MASK;
}

// Ensure:
// (1) MSB is reserved for the allocated flag,
// (2) the size of the allocation is large enough to be replaced by a
// free_node_t, guaranteeing the node can be freed, and
// (3) the usable size is a multiple of sizeof(size_t) while still being
// at least the requested size, guaranteeing alignment for each header_node_t
// and free_node_t and for the the pointers returned to the user.
//
// Note: This sets errno on an uncorrectable size and should thus only be used
// in allocation functions, which are not required to preserve errno.
static inline size_t normalize_allocation_size(size_t size) {
    if (size & SIZE_T_MSB_MASK) {
        errno = ENOMEM;
        return 0;
    } else if (size < MIN_ALLOC_SIZE) {
        return MIN_ALLOC_SIZE;
    } else if (size & POINTER_ALIGHMENT_MASK) {
        return size + sizeof(size_t) - (size & POINTER_ALIGHMENT_MASK);
    } else {
        return size;
    }
}

static inline void set_allocation_to_zero(void *ptr, size_t start_ind) {
    if (ptr) {
        // Set all new array entries to 0 by size_t if expanded.
        size_t *data = ptr + start_ind;
        size_t *end = ptr + get_allocated_size(get_node(ptr));
        while (data < end)
            *(data++) = 0;
    }
}

// Iterate through the free list until the first node with at least the
// requested size is found. Allocate that node and (if there is sufficient
// space for another allocation in the node) split a new free node off the
// end of the node.
static void *_malloc_unchecked(size_t size) {
    free_node_t *prev_free_node = free_list;
    while (prev_free_node->next_free) {
        free_node_t *free_node = prev_free_node->next_free;
        if (free_node->header.size >= size &&
            free_node->header.size - size >=
            sizeof(header_node_t) + MIN_ALLOC_SIZE) {
            // Enough space for this allocation and for another in free_node's
            // remaining space.

            // Split a new free node off the end of this node.
            free_node_t *new_free_node =
                (void *) free_node + sizeof(header_node_t) + size;
            new_free_node->header.size =
                free_node->header.size - size - sizeof(header_node_t);

            // Insert new_free_node after free_node in the header list.
            set_next_prev(free_node, (header_node_t *) new_free_node);
            new_free_node->header.prev = (header_node_t *) free_node;

            replace_in_free_list(free_node, new_free_node);

            // Update size and mark the node as allocated.
            free_node->header.size = size | SIZE_T_MSB_MASK;

            return get_usable_memory((header_node_t *) free_node);
        } else if (free_node->header.size >= size) {
            // Enough space for this allocation but not enough for another
            // allocation in free_node's remaining space

            // Mark the node as allocated.
            free_node->header.size |= SIZE_T_MSB_MASK;

            // Remove the newly allocated node from the free list.
            prev_free_node->next_free = free_node->next_free;
            if (free_node->next_free)
                free_node->next_free->prev_free = prev_free_node;

            return get_usable_memory((header_node_t *) free_node);
        }

        prev_free_node = free_node;
    }

    errno = ENOMEM;
    return NULL; // No free nodes of sufficient size
}

// Because POSIX does not specify whether free should preserve errno, this
// function preserves errno in case the caller relies on this behavior.
static void _free_unchecked(free_node_t *node) {
    node->header.size &= SIZE_T_REST_MASK; // Mark unallocated and correct size

    header_node_t *next = get_next_node_f(node);
    int next_is_free = next && !is_allocated(next);

    header_node_t *prev = node->header.prev;
    int prev_is_free =
    ((free_node_t *) prev != free_list) && !is_allocated(prev);

    if (prev_is_free && next_is_free) { // Merge with surrounding nodes
        free_node_t *free_prev = (free_node_t *) prev;
        free_node_t *free_next = (free_node_t *) next;

        prev->size +=
            2 * sizeof(header_node_t) + node->header.size + next->size;

        // Remove free_next from the free list.
        remove_from_free_list(free_next);

        // Remove node and free_next from the header list.
        set_next_prev(free_next, prev);
    } else if (prev_is_free) { // Merge with prev node
        prev->size += sizeof(header_node_t) + node->header.size;

        // Remove node from the header list.
        if (next)
            next->prev = prev;
    } else if (next_is_free) { // Merge with next node
        free_node_t *free_next = (free_node_t *) next;

        node->header.size += sizeof(header_node_t) + next->size;

        replace_in_free_list(free_next, node);

        // Remove free_next from the header list
        set_next_prev(free_next, (header_node_t *) node);
    } else {
        // Insert at the start of the free list.
        insert_in_free_list(free_list, node);
    }
}

static inline void *try_shrink_allocation_into_next(
    void *data, header_node_t *node, free_node_t *next,
    size_t old_size, size_t new_size) {

    size_t decrease = old_size - new_size;

    // Shrink node and mark node as allocated.
    node->size = new_size | SIZE_T_MSB_MASK;

    // Create a new free node at the start of the newly unallocated space.
    free_node_t *new_free_node = (void *) next - decrease;

    // Note: the order in which the fields of new_free_node are set below
    // MUST not be changed. The order allows decrease (which is at least
    // sizeof(size_t)) to be less than sizeof(free_node_t) without
    // corrupting the header list or free list.

    // Replace next with new_free_node in the header list.
    new_free_node->header.prev = node;
    set_next_prev(next, (header_node_t *) new_free_node);

    // Add the newly unallocated space to the size of the free node after node.
    new_free_node->header.size = next->header.size + decrease;

    replace_in_free_list_before(next, new_free_node);

    return data;
}

static inline void *try_shrink_allocation_and_split(
    void *data, header_node_t *node, header_node_t *next,
    size_t old_size, size_t new_size) {

    size_t decrease = old_size - new_size;
    if (decrease < MIN_SHRINK_SPLIT_SIZE)
        return data; // Do not make a new small free node

    // Shrink node and mark node as allocated.
    node->size = new_size | SIZE_T_MSB_MASK;

    // Create a new free node at the start of the newly unallocated space.
    free_node_t *new_free_node =
        (void *) node + sizeof(header_node_t) + new_size;

    // Assign the newly unallocated space to the new free node.
    new_free_node->header.size = decrease - sizeof(header_node_t);

    // Insert new_free_node at start of free list.
    insert_in_free_list(free_list, new_free_node);

    // Insert new_free_node after node in the header list.
    new_free_node->header.prev = node;
    next->prev = (header_node_t *) new_free_node;

    return data;
}

static inline void *try_expand_allocation_and_move(
    void *data, header_node_t *node, size_t old_size, size_t new_size) {

    void *new_location = _malloc_unchecked(new_size);
    if (!new_location)
        return NULL;

    memcpy(new_location, data, old_size);

    _free_unchecked((free_node_t *) get_node(data));

    return new_location;
}

static inline void *try_expand_allocation_into_next(
    void *data, header_node_t *node, free_node_t *next,
    size_t old_size, size_t new_size) {

    size_t increase = new_size - old_size;
    if (increase <= next->header.size - MIN_ALLOC_SIZE) {
        // Split next and merge the first part into node.

        // Expand size and mark node as allocated.
        node->size = new_size | SIZE_T_MSB_MASK;

        free_node_t *new_free_node = (void *) next + increase;

        // Note: the order in which the fields of new_free_node are set below
        // MUST not be changed. The order allows increase (which is at least
        // sizeof(size_t)) to be less than sizeof(free_node_t) without
        // corrupting the header list or free list.

        replace_in_free_list(next, new_free_node);

        // Remove next from the header list.
        set_next_prev(next, (header_node_t *) new_free_node);

        // Set the size of new_free_node to the remaining size, and connect
        // new_free_node's backwards link in the header list.
        new_free_node->header.size = next->header.size - increase;
        new_free_node->header.prev = node;

        return data;
    } else if (increase <= sizeof(header_node_t) + next->header.size) {
        // Merge next entirely into node.

        // Add the size of next and next's header to node's size and mark node
        // as allocated.
        node->size =
            (old_size + sizeof(header_node_t) + next->header.size) |
            SIZE_T_MSB_MASK;

        remove_from_free_list(next);

        // Remove next from the header list
        set_next_prev(next, node);

        return data;
    } else {
        // Move node

        return try_expand_allocation_and_move(data, node, old_size, new_size);
    }
}

static inline void *_realloc_unchecked(
    void *ptr, header_node_t *node, size_t size, size_t *old_size_out) {

    size_t old_size = get_allocated_size(node);
    *old_size_out = old_size;

    header_node_t *next = get_next_node(node, old_size);
    int next_is_free = !is_allocated(next);

    if (old_size > size) { // Shrink
        // Merge the removed trailing memory with the next node if the next
        // node is free. Otherwise, do not change any nodes.
        return next_is_free ?
            try_shrink_allocation_into_next(
                ptr, node, (free_node_t *) next, old_size, size) :
            try_shrink_allocation_and_split(ptr, node, next, old_size, size);
    } else if (old_size < size) { // Grow
        return next_is_free ?
            try_expand_allocation_into_next(
                ptr, node, (free_node_t *) next, old_size, size) :
            try_expand_allocation_and_move(ptr, node, old_size, size);
    } else {
        return ptr; // Old and new allocation sizes are the same.
    }
}

static inline void *_malloc_no_unlock(size_t size) {
    size = normalize_allocation_size(size);
    if (size == 0) // Size was uncorrectable
        return NULL;

    LOCK;
    return _malloc_unchecked(size);
}

void *malloc(size_t size) {
    size = normalize_allocation_size(size);
    if (size == 0) // Size was uncorrectable
        return NULL;

    LOCK;
    void *ptr = _malloc_unchecked(size);
    UNLOCK;

    return ptr;
}

void *mallocarray(size_t nmemb, size_t size) {
    CALCULATE_ARRAY_SIZE_CHECKED

    return malloc(byte_size);
}

void *calloc(size_t nmemb, size_t size) {
    CALCULATE_ARRAY_SIZE_CHECKED

    byte_size = normalize_allocation_size(byte_size);
    if (byte_size == 0) // Size was uncorrectable
        return NULL;

    LOCK;

    void *ptr = _malloc_unchecked(byte_size);

    // If ptr not null, efficiently set all the allocated space to 0 by size_t.
    set_allocation_to_zero(ptr, 0);

    UNLOCK;

    return ptr;
}

static void *_realloc_no_unlock(void *ptr, size_t size, size_t *old_size) {
    // Signal locked iff return not NULL or *old_size != 0.
    // Also, if !ptr and malloc succeeds, signal recalloc to set entire new
    // allocation to 0.
    *old_size = 0;

    if (!ptr) {
        void *p = _malloc_no_unlock(size);
        if (!p)
            UNLOCK; // Ensure lock signaling constraint
        return p;
    }

    if (size == 0) {
        free(ptr);
        return NULL;
    }

    // Ensure ptr is size_t-aligned.
    if (is_unaligned(ptr)) {
        errno = EINVAL;
        return NULL;
    }

    size = normalize_allocation_size(size);
    if (size == 0) // Size was uncorrectable
        return NULL;

    // Ensure ptr is somewhere within the heap's memory.
    if (allocation_out_of_heap_range(ptr)) {
        errno = EFAULT;
        return NULL;
    }

    // Move back from caller's usable space to header.
    header_node_t *node = get_node(ptr);

    LOCK;

    // Ensure node resembles an allocated node.
    // This does not detect whether node actually refers to an allocated node,
    // or to an unallocated node that has been tampered with, or to memory
    // within the heap that coincidentally/maliciously resembles a node.
    if (!is_allocated(node)) {
        UNLOCK;
        errno = EPERM;
        return NULL;
    }

    return _realloc_unchecked(ptr, node, size, old_size);
}

static inline void *_realloc(void *ptr, size_t size, size_t *old_size) {
    void *p = _realloc_no_unlock(ptr, size, old_size);

    if (p || *old_size != 0) // Lock still held
        UNLOCK;

    return p;
}

void *realloc(void *ptr, size_t size) {
    size_t ignored;
    return _realloc(ptr, size, &ignored);
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
    CALCULATE_ARRAY_SIZE_CHECKED

    return realloc(ptr, byte_size);
}

void *recalloc(void *ptr, size_t nmemb, size_t size) {
    CALCULATE_ARRAY_SIZE_CHECKED

    size_t old_size;
    void *p = _realloc_no_unlock(ptr, byte_size, &old_size);

    // If p not null, efficiently set all added space to 0 by size_t.
    set_allocation_to_zero(p, old_size);

    if (p || old_size != 0) // Lock still held
        UNLOCK;

    return p;
}

void free(void *ptr) {
    // Ensure ptr is aligned, not null, and somewhere in the heap's memory.
    if (is_unaligned(ptr))
        return;

    if (allocation_out_of_heap_range(ptr))
        return;

    // Move back from start of caller memory to node header.
    header_node_t *node = get_node(ptr);

    LOCK;

    // Ensure node resembles an allocated node before freeing.
    // This does not detect whether node actually refers to an allocated node,
    // or to an unallocated node that has been tampered with, or to memory
    // within the heap that coincidentally/maliciously resembles a node.
    if (is_allocated(node))
        _free_unchecked((free_node_t *) node);

    UNLOCK;
}

__attribute__ ((constructor))
void yada_init() {
    LOCK;

    if (free_list)
        return; // Already initialized

    void *uninitialized = mmap(
        0,
        HEAP_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0
    );

    if (MAP_FAILED == uninitialized) {
        exit(errno);
    }

    // Place the dummy head of the free list at the start of the heap's memory
    free_list = uninitialized;
    free_list->header.prev = NULL;
    free_list->header.size = MIN_ALLOC_SIZE;

    // Place the first usable node immediately after the dummy node.
    // The size of free_list and this node's header are subtracted from the
    // heap's memory size to find the size of the memory usable by the caller.
    free_node_t *first_node = uninitialized + sizeof(free_node_t);
    first_node->header.prev = (header_node_t *) free_list;
    first_node->header.size =
        HEAP_SIZE - sizeof(free_node_t) - sizeof(header_node_t);
    first_node->next_free = NULL;
    first_node->prev_free = uninitialized;

    free_list->next_free = first_node;
    free_list->prev_free = NULL;

    UNLOCK;
}
