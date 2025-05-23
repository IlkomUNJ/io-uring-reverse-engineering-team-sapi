// SPDX-License-Identifier: GPL-2.0

#include "alloc_cache.h"

/*
The io_alloc_cache_free function is responsible for freeing the resources associated with an io_alloc_cache structure. 
This structure is likely used to manage a cache of pre-allocated memory entries in the context of the io_uring subsystem or a similar kernel component. 
The function takes two parameters: a pointer to the io_alloc_cache structure (cache) and a function pointer (free) that specifies how individual cache entries should be freed.
*/
void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *))
{
	void *entry;

	if (!cache->entries)
		return;

	while ((entry = io_alloc_cache_get(cache)) != NULL)
		free(entry);

	kvfree(cache->entries);
	cache->entries = NULL;
}

/* returns false if the cache was initialized properly */
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes)
{
	cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);
	if (!cache->entries)
		return true;

	cache->nr_cached = 0;
	cache->max_cached = max_nr;
	cache->elem_size = size;
	cache->init_clear = init_bytes;
	return false;
}

/*
The io_cache_alloc_new function is responsible for allocating a new memory object for an io_alloc_cache structure. 
This function is likely used in the context of the io_uring subsystem or a similar kernel component to manage memory for cached objects. 
It takes two parameters: a pointer to the io_alloc_cache structure (cache) and a gfp_t value (gfp), which specifies the memory allocation flags used by the kernel's memory allocator.
*/
void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = kmalloc(cache->elem_size, gfp);
	if (obj && cache->init_clear)
		memset(obj, 0, cache->init_clear);
	return obj;
}
