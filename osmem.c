// SPDX-License-Identifier: BSD-3-Clause

// sursa: https://danluu.com/malloc-tutorial/
// sursa: https://moss.cs.iit.edu/cs351/slides/slides-malloc.pdf

#include "osmem.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include "block_meta.h"

#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define CALLOC_THRESHOLD ((size_t)(getpagesize()))

// inceputul listei
struct block_meta *global_base = (struct block_meta *)0;
struct block_meta *last = (struct block_meta *)0;
int prealloc;
int prealloc_realloc;

/* functie pentru a obtine memorie cu sbrk */
struct block_meta *request_more_memory_brk(size_t size)
{
	if (size <= 0)
		return NULL;

	struct block_meta *block;

	block = sbrk(0);
	void *request = sbrk(size);

	DIE(request != (void *)block, "sbrk");

	block->status = STATUS_ALLOC;
	block->size = size;
	if (last == NULL) {
		block->next = NULL;
		block->prev = NULL;
		last = block;
	} else {
		block->prev = last;
		block->next = last->next;
		last->next = block;
		last = block;
	}
	return block;
}
/* functie pentru a obtine memorie cu mmap */
struct block_meta *request_more_memory_mmap(size_t size)
{
	if (size <= 0)
		return NULL;
	struct block_meta *block;

	block = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	DIE((void *)block == MAP_FAILED, "mmap");
	if (block == NULL)
		return NULL;
	block->status = STATUS_MAPPED;
	block->size = size;

	return block;
}
/* functie pentru a truncherea blocului */
void split_block(struct block_meta *block, size_t size)
{
	size_t remaining_size = block->size - size;

	if (remaining_size >= (META_SIZE + 8)) {
		struct block_meta *new_block = (struct block_meta *)((char *)block + size);

		if (block == last)
			last = new_block;
		new_block->prev = block;
		new_block->next = block->next;
		if (block->next != NULL)
			block->next->prev = new_block;
		block->next = new_block;
		new_block->size = remaining_size;
		new_block->status = STATUS_FREE;
		block->size = size;
	}
}

void coalesce_blocks(struct block_meta *block)
{
	if (block != NULL && block->status == STATUS_FREE) {
		// coalesce cu blocul urmator
		if (block->next != NULL && block->next->status == STATUS_FREE) {
			block->size = block->size + block->next->size + META_SIZE;
			block->next = block->next->next;
			if (block->next != NULL)
				block->next->prev = block;
		}

		// coalesce cu blocul anterior
		if (block->prev != NULL && block->prev->status == STATUS_FREE) {
			block->prev->size = block->prev->size + block->size + META_SIZE;
			block->prev->next = block->next;
			if (block->next != NULL)
				block->next->prev = block->prev;

			// am actualizat pointerul last
			if (block == last)
				last = block->prev;
			block = block->prev;
		}
	}
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	struct block_meta *block = global_base;
	struct block_meta *pblock;

	size = ALIGN(size + META_SIZE);
	// prealocare
	if (prealloc == 0) {
		if (size < MMAP_THRESHOLD) {
			pblock = request_more_memory_brk(MMAP_THRESHOLD);
			if (pblock->size > size)
				split_block(pblock, size);
		} else {
			pblock = request_more_memory_mmap(size);
		}
		// am actualizat global_base
		if (pblock != NULL && pblock->status != STATUS_MAPPED) {
			prealloc = 1;
			global_base = pblock;
			global_base->size = pblock->size;
		}
		return (void *)(pblock + 1);
	}
	// caut un bloc liber
	while (block != NULL) {
		if (block->status != STATUS_FREE) {
			block = block->next;
		} else {
			if (block->size >= size) {
				if (size >= MMAP_THRESHOLD)
					block->status = STATUS_MAPPED;
				if (size < MMAP_THRESHOLD) {
					block->status = STATUS_ALLOC;
					if (block->size > size)
						split_block(block, size);
				}
				if (global_base == NULL && block->status != STATUS_MAPPED)
					global_base = block;
				return (void *)(block + 1);
			}
				block = block->next;
		}
	}

		// daca nu am gasit un bloc liber, aloc memorie
		if (last->status != STATUS_FREE) {
			struct block_meta *new_block;

			if (size >= MMAP_THRESHOLD)
				new_block = request_more_memory_mmap(size);
			if (size < MMAP_THRESHOLD) {
				new_block = request_more_memory_brk(size);
				if (new_block->size > size)
					split_block(new_block, size);
			}
			if (new_block->status != STATUS_MAPPED) {
				if (global_base == NULL) {
					global_base = new_block;
					last = new_block;
				}
			}
			return (void *)(new_block + 1);
		}
		// expandam
		size_t new_block = (char *)sbrk(0) - (char *)last;
		// verific daca trebuie expandat sau redus heap-ul
		if (new_block < size) {
			sbrk(size - new_block);
			return (void *)(last + 1);
		}
		return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;
	struct block_meta *search = (struct block_meta *)ptr - 1;

	if (search->status == STATUS_MAPPED) {
		int result = munmap(search, search->size);

		DIE(result < 0, "munmap");

	} else {
		search->status = STATUS_FREE;
		coalesce_blocks(search);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size == 0 || nmemb == 0)
		return NULL;

	struct block_meta *block = global_base;

	size = ALIGN(size * nmemb) + META_SIZE;

	if (size >= CALLOC_THRESHOLD) {
		block = request_more_memory_mmap(size);
		if (block != NULL) {
			memset((block + 1), 0, size);
			return (void *)(block + 1);
		}
	} else {
		block = os_malloc(size - META_SIZE);
		if (block != NULL) {
			memset(block, 0, size - META_SIZE);
			return (void *)block;
		}
	}
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (ptr == NULL)
		return os_malloc(size);
	size = ALIGN(size + META_SIZE);

	struct block_meta *block = (struct block_meta *)ptr - 1;
	struct block_meta *realloc_block;

	if (size == block->size)
		return ptr;
	if (block == NULL || block->status == STATUS_FREE)
		return NULL;

	if (size < MMAP_THRESHOLD) {
		// din old - brk in new -brk
		if (block->status == STATUS_ALLOC) {
			if (block->size > size) {
				split_block(block, size);
				return ptr;
			}
			if (block->size < size) {
				// daca e ultimul bloc -> expand
				if (block->next == NULL) {
					size_t new_block = (char *)sbrk(0) - (char *)last;

					sbrk(size - new_block);
					return (void *)(last + 1);
				}
				// coalesce cu blocul urmator daca se poate
				if (block->next != NULL && block->next->status == STATUS_FREE && block->status == STATUS_ALLOC
				&& size < MMAP_THRESHOLD) {
					if (block->size + block->next->size + META_SIZE >= size) {
						block->size = block->size + block->next->size + META_SIZE;
						// am sters urmatorul bloc din lista
						block->next = block->next->next;
						if (block->next != NULL)
							block->next->prev = block;
						// i-am dat split pt ca block->size > size
						split_block(block, size - META_SIZE);
						return ptr;
					}
				}
				// altfel, malloc pt alocare
				if (block->size < size && block->next->status == STATUS_ALLOC && block->prev->status == STATUS_ALLOC) {
					realloc_block = os_malloc(size - META_SIZE);
					memcpy(realloc_block, ptr, size);
					os_free(ptr);
					return realloc_block;
				}
			}
		}

		// din old mmap in new brk
		if (block->status == STATUS_MAPPED && block->size > size) {
			realloc_block = os_malloc(size - META_SIZE);
			memcpy(realloc_block, ptr, size);
			os_free(ptr);
			return realloc_block;
		}
	} else {
		// daca new -> mmap
		if (prealloc_realloc == 0) {
			prealloc = 0;
			prealloc_realloc = 1;
		}
		realloc_block = os_malloc(size - META_SIZE);
		memcpy(realloc_block, ptr, size);
		os_free(ptr);
		return realloc_block;
	}
	return NULL;
}
