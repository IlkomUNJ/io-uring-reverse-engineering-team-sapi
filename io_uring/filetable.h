// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FILE_TABLE_H
#define IOU_FILE_TABLE_H

#include <linux/file.h>
#include <linux/io_uring_types.h>
#include "rsrc.h"

bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table, unsigned nr_files);
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table);

int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot);
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
				unsigned int file_slot);
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset);

int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg);

io_req_flags_t io_file_get_flags(struct file *file);

/*
The io_file_bitmap_clear function provides an efficient and reliable mechanism for managing file descriptor slots in the io_uring subsystem. 
By clearing a specific bit in the bitmap and updating the allocation hint, it supports the dynamic and scalable nature of asynchronous I/O operations. 
Its design ensures that resources are reused effectively while maintaining the integrity of the file descriptor table.
*/
static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(!test_bit(bit, table->bitmap));
	__clear_bit(bit, table->bitmap);
	table->alloc_hint = bit;
}

/*
The io_file_bitmap_set function provides an efficient and reliable mechanism for managing file descriptor slots in the io_uring subsystem. 
By setting a specific bit in the bitmap and updating the allocation hint, it supports the dynamic and scalable nature of asynchronous I/O operations. 
Its design ensures that resources are tracked effectively while maintaining the integrity of the file descriptor table.
*/
static inline void io_file_bitmap_set(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(test_bit(bit, table->bitmap));
	__set_bit(bit, table->bitmap);
	table->alloc_hint = bit + 1;
}

#define FFS_NOWAIT		0x1UL
#define FFS_ISREG		0x2UL
#define FFS_MASK		~(FFS_NOWAIT|FFS_ISREG)

/*
This function retrieves the flags associated with a specific file descriptor slot represented by an io_rsrc_node. 
The file_ptr field in the node structure encodes both a pointer to the file and additional flags. 
*/
static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
{

	return (node->file_ptr & ~FFS_MASK) << REQ_F_SUPPORT_NOWAIT_BIT;
}

/*
This function retrieves the actual file pointer from an io_rsrc_node. The file_ptr field in the node encodes both the file pointer and flags.
*/
static inline struct file *io_slot_file(struct io_rsrc_node *node)
{
	return (struct file *)(node->file_ptr & FFS_MASK);
}

/*
This function sets a file descriptor slot in an io_rsrc_node with a given file pointer and its associated flags.
*/
static inline void io_fixed_file_set(struct io_rsrc_node *node,
				     struct file *file)
{
	node->file_ptr = (unsigned long)file |
		(io_file_get_flags(file) >> REQ_F_SUPPORT_NOWAIT_BIT);
}

/*
This function sets the allocation range for file descriptor slots in an io_ring_ctx structure.
*/
static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx,
						 unsigned off, unsigned len)
{
	ctx->file_alloc_start = off;
	ctx->file_alloc_end = off + len;
	ctx->file_table.alloc_hint = ctx->file_alloc_start;
}

#endif
