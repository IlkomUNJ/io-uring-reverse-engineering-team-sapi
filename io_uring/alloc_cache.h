#ifndef IOU_ALLOC_CACHE_H
#define IOU_ALLOC_CACHE_H

#include <linux/io_uring_types.h>

/*
 * Don't allow the cache to grow beyond this size.
 */
#define IO_ALLOC_CACHE_MAX	128

void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *));
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes);

void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp);

/*
The io_alloc_cache_put function is a static inline function designed to add an entry to an io_alloc_cache structure, which is likely used to manage a cache of pre-allocated memory objects in the context of the io_uring subsystem or a similar kernel component. 
The function takes two parameters: a pointer to the io_alloc_cache structure (cache) and a pointer to the memory object (entry) that needs to be added to the cache. It returns a boolean value indicating whether the operation was successful.
*/
static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
				      void *entry)
{
	if (cache->nr_cached < cache->max_cached) {
		if (!kasan_mempool_poison_object(entry))
			return false;
		cache->entries[cache->nr_cached++] = entry;
		return true;
	}
	return false;
}

/*
The io_alloc_cache_get function is a static inline function designed to retrieve an entry from an io_alloc_cache structure, which is likely used to manage a cache of pre-allocated memory objects in the context of the io_uring subsystem or a similar kernel component. 
The function takes a single parameter: a pointer to the io_alloc_cache structure (cache). It returns a pointer to the retrieved memory object or NULL if the cache is empty.
*/
static inline void *io_alloc_cache_get(struct io_alloc_cache *cache)
{
	if (cache->nr_cached) {
		void *entry = cache->entries[--cache->nr_cached];

		/*
		 * If KASAN is enabled, always clear the initial bytes that
		 * must be zeroed post alloc, in case any of them overlap
		 * with KASAN storage.
		 */
#if defined(CONFIG_KASAN)
		kasan_mempool_unpoison_object(entry, cache->elem_size);
		if (cache->init_clear)
			memset(entry, 0, cache->init_clear);
#endif
		return entry;
	}

	return NULL;
}

/*
The io_cache_alloc function is responsible for allocating a memory object from the cache. 
It takes two parameters: a pointer to the io_alloc_cache structure (cache) and a gfp_t value (gfp), which specifies the memory allocation flags used by the kernel's memory allocator.
*/
static inline void *io_cache_alloc(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = io_alloc_cache_get(cache);
	if (obj)
		return obj;
	return io_cache_alloc_new(cache, gfp);
}

/*
The io_cache_free function is responsible for freeing a memory object back to the cache or releasing it entirely if the cache is full. 
It takes two parameters: a pointer to the io_alloc_cache structure (cache) and a pointer to the memory object (obj) to be freed.
*/
static inline void io_cache_free(struct io_alloc_cache *cache, void *obj)
{
	if (!io_alloc_cache_put(cache, obj))
		kfree(obj);
}

#endif
