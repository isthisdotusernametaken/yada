#include "yada_heap.h"

#include <stdio.h>
#include <stdint.h>


#define DELIMITER_WIDTH 97

#define SIZE_T_PER_LINE 4


extern free_node_t *free_list;

static inline size_t is_allocated(header_node_t *node) {
    return node->size & SIZE_T_MSB_MASK;
}

static inline size_t get_size(header_node_t *node) {
    return is_allocated(node) ? node->size & SIZE_T_REST_MASK : node->size;
}

static inline header_node_t *get_node(void *ptr) {
    return ptr - sizeof(header_node_t);
}

static inline header_node_t *get_next(header_node_t *node) {
    void *next = (void *) node + sizeof(header_node_t) + get_size(node);

    return next < (void *) free_list + HEAP_SIZE ? next : NULL;
}

static void print_delimiter_line() {
    for (int i = 0; i < DELIMITER_WIDTH; i++)
        putchar('-');
    putchar('\n');
}

static inline void print_node(header_node_t *node, header_node_t *prev) {
    print_delimiter_line();

    printf(is_allocated(node) ? " A " : "   ");
    printf("%p prev:%c size:%-16zu ",
           node, node->prev == prev ? 'G' : 'X', get_size(node));

    // Always show free_node_t information in case printing within allocator
    // functions, when nodes may be in intermediate states.
    free_node_t *free_node = (free_node_t *) node;
    printf("nextf:%p prevf:%p\n",
           free_node->next_free, free_node->prev_free);
}

void print_heap() {
    header_node_t *node = (header_node_t *) free_list;
    header_node_t *prev = NULL;
    for (; node ; prev = node, node = get_next(node))
        print_node(node, prev);

    print_delimiter_line();
}

void print_allocation(void *ptr) {
    size_t *p = ptr;
    size_t *end = ptr + get_size(get_node(ptr));
    while (p < end - SIZE_T_PER_LINE + 1) {
        printf("%p:", p);
        for (int i = 0; i < SIZE_T_PER_LINE; i++, p++)
            printf(" %35zu", *p);
        puts("");
    }

    // Print remaining on partial line.
    if (p < end) {
        printf("%p:", p);
        while (p < end)
            printf(" %35zu", *(p++));
        puts("");
    }
}
