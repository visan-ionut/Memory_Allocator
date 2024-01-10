// SPDX-License-Identifier: BSD-3-Clause
#include <sys/mman.h>

#include "osmem.h"
#include "block_meta.h"
#include <bits/mman-linux.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

//Padding size
#define PADDING 8

//Malloc MMAP_THRESHOLD
#define MMAP_THRESHOLD (128 * 1024)

#define PAGE_SIZE 4096

//Size of block structure
#define BLOCK_SIZE sizeof(struct block_meta)

//Booleans
#define FALSE '0'
#define TRUE '1'


//Stores list of blocks and heap initiation
typedef struct Heap
{
	struct block_meta *block_list;
	char heap_start;
} Heap_st;

//Initializes heap
Heap_st MyHeap = {
	.block_list = NULL,
	.heap_start = FALSE
};

//Computes padding of size with an alignment to 8 bytes
size_t get_padding(size_t size)
{
	return (size_t)(PADDING * ((PADDING - 1 + (int)size) / PADDING));
}

// Initializes block
void set_block(struct block_meta *block, size_t total_size, int status,
			   struct block_meta *prev, struct block_meta *next)
{
	block->size = total_size;
	block->status = status;
	block->prev = prev;
	block->next = next;
}

// Allocates memory for chuncks bigger then 'MMAP_THRESHOLD using mmap
void *map_block(size_t total_size, int type)
{

	void *allocated;
	struct block_meta *block, *iter;

	allocated = mmap(NULL, total_size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	
	//ERROR CHECK
	DIE(allocated == MAP_FAILED, "mmap failed");

	//Sets memory to 0 if calloc
	if (type == 0)
	{
		memset(allocated, 0, total_size);
	}

	//Set block
	block = (struct block_meta *)allocated;
	set_block(block, total_size, STATUS_ALLOC, NULL, NULL);

	//Add block to the list
	if (MyHeap.heap_start == FALSE)
	{	
		//list is empty
		MyHeap.block_list = block;
		MyHeap.heap_start = TRUE;
	}
	else
	{
		//list is initialized
		iter = MyHeap.block_list;
		if (iter != NULL)
		{
			while (iter->next != NULL)
			{
				iter = iter->next;
			}
			iter->next = block;
			block->prev = iter;
		}
	}

	return allocated;
}

//Merges adjacent free blocks
void coalesce()
{

	void *heap_brk;

	struct block_meta *block, *iter;

	char coalesced = FALSE;

	iter = MyHeap.block_list;

	heap_brk = sbrk(0);

	//Searches for adjacent free blocks
	while (iter != NULL)
	{
		coalesced = FALSE;

		//If current block isnt last
		if ((size_t)iter + iter->size != (size_t)heap_brk)
		{
			//Next block
			block = (struct block_meta *)((size_t)iter + iter->size);

			if ((iter->status == STATUS_FREE) && block->status == STATUS_FREE)
			{
				//Combines blocks
				iter->size += block->size;

				if (block->prev != NULL)
				{
					block->prev->next = block->next;
				}

				if (block->next != NULL)
				{
					block->next->prev = block->prev;
				}

				coalesced = TRUE;
			}
		}
		if (coalesced == FALSE)
			iter = iter->next;
	}
}

//Reusing memory blocks
void *split(size_t total_size, size_t padded_block)
{
	void *allocated;

	struct block_meta *block, *iter;

	iter = MyHeap.block_list;

	//Searches for empty blocks
	while (iter != NULL)
	{

		if (iter->size >= total_size + padded_block && iter->status == STATUS_FREE)
		{
			//Splits the block in 2

			//free memory block
			block = (struct block_meta *)((size_t)iter + total_size);
			block->size = iter->size - total_size;
			block->prev = iter;
			block->next = iter->next;
			block->status = STATUS_FREE;
			if (block->next != NULL)
			{
				block->next->prev = block;
			}

			//split block
			iter->size = total_size;
			iter->next = block;
			iter->status = STATUS_MAPPED;
			allocated = iter;
			return allocated;
		}
		iter = iter->next;
	}
	return NULL;
}

//Realocks memory to an existing block
void *realoc_existing(size_t total_size, int type)
{

	void *allocated;

	struct block_meta *iter;

	iter = MyHeap.block_list;

	while (iter != NULL)
	{
		//If block is free and has enough memory narks it as STATUS_MAPPED
		if (iter->size >= total_size && iter->status == STATUS_FREE)
		{
			iter->status = STATUS_MAPPED;
			iter->size = total_size;

			allocated = iter;

			if (type == 0)
			{
				memset(allocated + BLOCK_SIZE, 0, total_size - BLOCK_SIZE);
			}
			return allocated;
		}
		iter = iter->next;
	}

	return NULL;
}

//Extends last block
void *extend_last(size_t total_size)
{

	void *heap_brk, *allocated;

	struct block_meta *iter;

	heap_brk = sbrk(0);

	iter = MyHeap.block_list;

	while (iter != NULL)
	{
		if (((size_t)iter + iter->size) == (size_t)heap_brk && iter->status == STATUS_FREE)
		{
			sbrk(total_size - iter->size);
			iter->status = STATUS_MAPPED;
			iter->size = total_size;
			allocated = iter;
			return allocated;
		}
		iter = iter->next;
	}

	return NULL;
}


void *os_malloc(size_t size)
{
	// Nothing to be allocated
	if (size == 0)
		return NULL;

	void *allocated;
	void *heap_brk;

	char reused = FALSE;

	//Adds padding
	size_t padded_block = get_padding(BLOCK_SIZE);

	size_t padded_load = get_padding(size);

	size_t total_size = padded_block + padded_load;

	struct block_meta *iter = NULL, *block = NULL;

	//Chcks for threshold
	if (total_size >= MMAP_THRESHOLD)
	{
		// MAP
		allocated = map_block(total_size, 1);
	}
	else
	{

		// COALESCE
		if (MyHeap.heap_start == TRUE)
		{
			coalesce();
		}

		if (MyHeap.heap_start == TRUE)
		{

			// SPLIT BLOCK
			allocated = split(total_size, padded_block);
			if (allocated != NULL)
				reused = TRUE;

			// REALOCATION
			if (reused == FALSE)
			{
				allocated = realoc_existing(total_size, 1);
				if (allocated != NULL)
					reused = TRUE;
			}

			// EXTENDS LAST BLOCK
			if (reused == FALSE)
			{
				allocated = extend_last(total_size);
				if (allocated != NULL)
					reused = TRUE;
			}
		}

		if (reused == FALSE)
		{
			
			if (MyHeap.heap_start == FALSE)
			{

				heap_brk = sbrk(0);
				

				DIE(sbrk(MMAP_THRESHOLD) == (void *)-1, "heap initialization failed");

				block = (struct block_meta *)heap_brk;

				// Set first block from heap
				set_block(block, MMAP_THRESHOLD, STATUS_MAPPED, NULL, NULL);

				MyHeap.block_list = block;

				//Init heap
				allocated = heap_brk;
				MyHeap.heap_start = TRUE;
			}
			else
			{
				// Add memory to blocklist and last block
				heap_brk = sbrk(0);

				DIE(sbrk(total_size) == (void *)-1, "heap initialization failed");

				block = (struct block_meta *)heap_brk;

				set_block(block, total_size, STATUS_MAPPED, NULL, NULL);

				iter = MyHeap.block_list;
				while (iter->next != NULL)
				{
					iter = iter->next;
				}
				iter->next = block;
				block->prev = iter;

				allocated = heap_brk;
			}
		}
	}

	return allocated + padded_block;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
	return;

	
	struct block_meta *block = ptr - sizeof(struct block_meta);
	if (block->status == STATUS_ALLOC)
	{
		//Free munmap
		if (block->prev == NULL)
		{
			if (block->next != NULL)
			{
				MyHeap.block_list = block->next;
			}
			else
				MyHeap.block_list = NULL;
		}
		munmap(ptr - sizeof(struct block_meta), block->size);
	}
	else
	{
		//brk allock free
		block->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	// Nothing to be allocated
	if (nmemb == 0 || size == 0)
		return NULL;

	void *allocated;
	void *heap_brk;

	char reused = FALSE;

	// Adds padding
	size_t padded_block = get_padding(BLOCK_SIZE);

	size_t padded_load = get_padding(size * nmemb);

	size_t total_size = padded_block + padded_load;

	struct block_meta *iter = NULL, *block = NULL;

	if (total_size >= PAGE_SIZE)
	{
		// MAP
		allocated = map_block(total_size, 0);
	}
	else
	{

		// COALESCE
		if (MyHeap.heap_start == TRUE)
		{
			coalesce();
		}

		if (MyHeap.heap_start == TRUE)
		{

			// SPLIT BLOCK
			allocated = split(total_size, padded_block);
			if (allocated != NULL)
				reused = TRUE;

			// REALOC
			if (reused == FALSE)
			{
				allocated = realoc_existing(total_size, 0);
				if (allocated != NULL)
					reused = TRUE;
			}

			// EXTEND LAST BLOCk
			if (reused == FALSE)
			{
				allocated = extend_last(total_size);
				if (allocated != NULL)
					reused = TRUE;
			}
		}

		if (reused == FALSE)
		{

			if (MyHeap.heap_start == FALSE)
			{

				heap_brk = sbrk(0);
				sbrk(MMAP_THRESHOLD);

				memset(heap_brk, 0, MMAP_THRESHOLD);
				block = (struct block_meta *)heap_brk;

				//Set first block from heap
				set_block(block, MMAP_THRESHOLD, STATUS_MAPPED, NULL, NULL);

				MyHeap.block_list = block;

				//Init heap
				allocated = heap_brk;
				MyHeap.heap_start = TRUE;
			}
			else
			{
				//Add memory to heap && block to list
				heap_brk = sbrk(0);

				sbrk(total_size);
				memset(heap_brk, 0, total_size);

				block = (struct block_meta *)heap_brk;

				set_block(block, total_size, STATUS_MAPPED, NULL, NULL);

				iter = MyHeap.block_list;
				while (iter->next != NULL)
				{
					iter = iter->next;
				}
				iter->next = block;
				block->prev = iter;

				allocated = heap_brk;
			}
		}
	}

	block = (struct block_meta *)allocated;
	return allocated + padded_block;
}

void *os_realloc(void *ptr, size_t size)
{
	return NULL;
}
