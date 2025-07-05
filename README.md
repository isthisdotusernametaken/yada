# Yet Another Dynamic Allocator (yada)
A thread-safe, chunk-based heap allocator implementing the standard C heap functions and other useful allocation functions.

## Usage
Compile a project with _yada.c_ to override the included heap allocation functions; _yada_heap.h_ must be in the include-path or otherwise available to _yada.c_.  

The header _yada.h_ must be included (or `mallocarray` and/or `recalloc` must be prototyped) if the yada-specific functions are used; similarly, if your compiler does not provide `reallocarray`, _yada.h_ or prototyping is required for code using the function.  

The function `void yada_init()` is declared in _yada_init.h_ and must be called before any allocation functions; however, the function is annotated with `__attribute__ ((constructor))` and thus will not need to be manually called with some compilers. The function is thread-safe, and any calls after the first have no effect on the heap, so it can be safely called manually if the constructor annotation will/may be ignored.  

Currently, `mmap` is used in `yada_init` to acquire the memory for the heap, and _yada.c_ thus includes `sys/mman.h`; `mmap` is a POSIX standard function but may **not be available on Windows**. Additionaly, _yada.c_ ensures thread safety with `pthread_mutex_t`, `pthread_mutex_lock`, and `pthread_mutex_unlock` from _pthread.h_, which is POSIX standard but is also **not available by default on Windows**.

## Configuration
The file _yada_heap.h_ provides the following configurable constants:
* `HEAP_SIZE`: The maximum number of bytes in the heap, including allocations and heap node data. This must be a multiple of `sizeof(size_t)`.
* `MIN_ALLOC_SIZE`: The lowest number of bytes that will be available in any successful allocation. This must be a multiple of `sizeof(size_t)` and must be at least `sizeof(free_node_t) - sizeof(header_node_t)`, which is `2 * sizeof(void *)`.
* `MIN_SHRINK_SPLIT_SIZE`: The lowest number of bytes that can be split into a new chunk after a shrinking reallocation. This must be at least `sizeof(free_node_t)`, which is `3 * sizeof(void *) + sizeof(size_t)`, barring alignment considerations when `size_t` and `void *` have different alignments. Larger values for this constant potentially (1) improve allocation speed by reducing the number of small chunks inserted at the start of the free list when reallocating but (2) increase the amount of memory usage by not maximally shrinking allocations when reallocating.

## Allocation Functions
The glibc and standard C functions were designed to match the guarantees of glibc's corresponding implementations regarding `errno` values/preservation, return values, parameter names, and handling of `NULL` and `0` arguments (as specified in malloc(3) from Linux man-pages 6.9.1).

The original function `mallocarray` implements `malloc` with `nmemb * size` overflow checking identical to that of `calloc`; the glibc requirements for `malloc` as described above are also met by `mallocarray`. The original function `recalloc` implements `realloc` with this overflow checking, additionally zeroing any memory added to the allocation; the glibc requirements for `realloc`  as described above are also met by `recalloc`.

### C Standard:
* `malloc(size_t size)`
* `calloc(size_t nmemb, size_t size)`
* `realloc(void *ptr, size_t size)`
* `free(void *ptr)`
### glibc:
* `reallocarray(void *ptr, size_t nmemb, size_t size)`
### yada:
* `mallocarray(size_t nmemb, size_t size)`
* `recalloc(void *ptr, size_t nmemb, size_t size)`

## Future Considerations
* Requested allocations with sizes sufficiently near the system's page size should be separately allocated through the system's page-mapping API. On Linux, this would likely involve deferring such `malloc`/`mallocarray`, `realloc`/`reallocarray`, and `free` calls to `mmap`, `mremap`, and `munmap`, respectively.

## Additional Notes
* When reallocating or deallocating, newly free memory is merged into adjacent free nodes whenever possible. This is intended to increase the average size of free nodes and reduce the number of free nodes, increasing allocation speed.
* The provided _yada_print.c_ file and its `void print_heap()` and `void print_allocation(void *ptr)` functions can be used to inspect the heap if _yada_print.h_ is included.
