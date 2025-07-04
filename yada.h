#pragma once

#include <stddef.h>


void *malloc(size_t size);

void *mallocarray(size_t nmemb, size_t size);

void *calloc(size_t nmemb, size_t size);

void *realloc(void *ptr, size_t size);

void *reallocarray(void *ptr, size_t nmemb, size_t size);

void *recalloc(void *ptr, size_t nmemb, size_t size);

void free(void *ptr);
