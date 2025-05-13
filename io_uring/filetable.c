// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"

/*
The io_file_bitmap_get function provides an efficient mechanism for allocating file descriptor slots in the io_uring subsystem. 
By leveraging a bitmap to track allocation status and using a wraparound search strategy, it ensures that slots are allocated in a manner that minimizes fragmentation and maximizes resource utilization. 
The function also incorporates safeguards, such as checking for an uninitialized bitmap, to maintain robustness and reliability in the allocation process.
*/
static int io_file_bitmap_get(struct io_ring_ctx *ctx)
{
	struct io_file_table *table = &ctx->file_table;
	unsigned long nr = ctx->file_alloc_end;
	int ret;

	if (!table->bitmap)
		return -ENFILE;

	do {
		ret = find_next_zero_bit(table->bitmap, nr, table->alloc_hint);
		if (ret != nr)
			return ret;

		if (table->alloc_hint == ctx->file_alloc_start)
			break;
		nr = table->alloc_hint;
		table->alloc_hint = ctx->file_alloc_start;
	} while (1);

	return -ENFILE;
}

/*
The io_alloc_file_tables function provides a robust mechanism for allocating file descriptor tables in the io_uring subsystem. 
By allocating both a resource data structure and a bitmap, it ensures that file descriptors can be efficiently tracked and managed. 
The function also incorporates error handling to clean up partially allocated resources, maintaining the integrity and reliability of the allocation process. 
This design is critical for supporting the dynamic and scalable nature of asynchronous I/O operations in io_uring.
*/
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table,
			  unsigned nr_files)
{
	if (io_rsrc_data_alloc(&table->data, nr_files))
		return false;
	table->bitmap = bitmap_zalloc(nr_files, GFP_KERNEL_ACCOUNT);
	if (table->bitmap)
		return true;
	io_rsrc_data_free(ctx, &table->data);
	return false;
}

/*
This function is responsible for freeing resources associated with a file descriptor table. 
It calls io_rsrc_data_free to release the resource data structure (table->data) and bitmap_free to deallocate the bitmap used for tracking file descriptor slots. 
Finally, it sets the bitmap pointer to NULL to prevent accidental reuse. This ensures proper cleanup of resources when a file table is no longer needed.
*/
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table)
{
	io_rsrc_data_free(ctx, &table->data);
	bitmap_free(table->bitmap);
	table->bitmap = NULL;
}

/*
The io_install_fixed_file function installs a fixed file descriptor into a specific slot in the file table. 
It validates the file and slot index, allocates a resource node (io_rsrc_node_alloc), and associates the file with the node. 
If the slot is successfully reset using io_reset_rsrc_node, the bitmap is updated to mark the slot as allocated. This function ensures that fixed file descriptors are installed in a thread-safe and consistent manner.
*/
static int io_install_fixed_file(struct io_ring_ctx *ctx, struct file *file,
				 u32 slot_index)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_rsrc_node *node;

	if (io_is_uring_fops(file))
		return -EBADF;
	if (!ctx->file_table.data.nr)
		return -ENXIO;
	if (slot_index >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_alloc(ctx, IORING_RSRC_FILE);
	if (!node)
		return -ENOMEM;

	if (!io_reset_rsrc_node(ctx, &ctx->file_table.data, slot_index))
		io_file_bitmap_set(&ctx->file_table, slot_index);

	ctx->file_table.data.nodes[slot_index] = node;
	io_fixed_file_set(node, file);
	return 0;
}

/*
The __io_fixed_fd_install function is a helper for installing fixed file descriptors. 
It supports both explicit slot allocation and dynamic slot allocation. For dynamic allocation, it uses io_file_bitmap_get to find the next available slot. 
After determining the slot, it delegates the installation to io_install_fixed_file. If successful and a slot was dynamically allocated, it returns the allocated slot index.
*/
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
			  unsigned int file_slot)
{
	bool alloc_slot = file_slot == IORING_FILE_INDEX_ALLOC;
	int ret;

	if (alloc_slot) {
		ret = io_file_bitmap_get(ctx);
		if (unlikely(ret < 0))
			return ret;
		file_slot = ret;
	} else {
		file_slot--;
	}

	ret = io_install_fixed_file(ctx, file, file_slot);
	if (!ret && alloc_slot)
		ret = file_slot;
	return ret;
}
/*
 * Note when io_fixed_fd_install() returns error value, it will ensure
 * fput() is called correspondingly.
 */
/*
The io_fixed_fd_install function wraps __io_fixed_fd_install and adds locking and cleanup. 
It acquires the io_ring_submit_lock to ensure thread safety during installation and calls fput to release the file reference if the installation fails. 
This function ensures that file descriptor installation is performed safely in a concurrent environment.
*/
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	io_ring_submit_lock(ctx, issue_flags);
	ret = __io_fixed_fd_install(ctx, file, file_slot);
	io_ring_submit_unlock(ctx, issue_flags);

	if (unlikely(ret < 0))
		fput(file);
	return ret;
}

/*
The io_fixed_fd_remove function removes a fixed file descriptor from a specific slot in the file table. 
It validates the slot index, retrieves the resource node using io_rsrc_node_lookup, and resets the slot using io_reset_rsrc_node. 
The bitmap is updated to mark the slot as free using io_file_bitmap_clear. This function ensures that file descriptors are properly removed and their resources are released.
*/
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset)
{
	struct io_rsrc_node *node;

	if (unlikely(!ctx->file_table.data.nr))
		return -ENXIO;
	if (offset >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_lookup(&ctx->file_table.data, offset);
	if (!node)
		return -EBADF;
	io_reset_rsrc_node(ctx, &ctx->file_table.data, offset);
	io_file_bitmap_clear(&ctx->file_table, offset);
	return 0;
}

/*
the io_register_file_alloc_range function registers a range of file descriptor slots for allocation. 
It validates the range, checks for overflow, and ensures that the range is within the bounds of the file table. 
If valid, it marks the specified range as available for allocation using io_file_table_set_alloc_range. This function provides flexibility in configuring the allocation range for file descriptors.
*/
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg)
{
	struct io_uring_file_index_range range;
	u32 end;

	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;
	if (check_add_overflow(range.off, range.len, &end))
		return -EOVERFLOW;
	if (range.resv || end > ctx->file_table.data.nr)
		return -EINVAL;

	io_file_table_set_alloc_range(ctx, range.off, range.len);
	return 0;
}
