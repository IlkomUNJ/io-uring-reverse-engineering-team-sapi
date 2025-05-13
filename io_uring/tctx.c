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
#include "tctx.h"

/*
 io_init_wq_offload() is called with ctx->uring_lock held
*/
static struct io_wq *io_init_wq_offload(struct io_ring_ctx *ctx,
					struct task_struct *task)
{
	struct io_wq_hash *hash;
	struct io_wq_data data;
	unsigned int concurrency;

	mutex_lock(&ctx->uring_lock);
	hash = ctx->hash_map;
	if (!hash) {
		hash = kzalloc(sizeof(*hash), GFP_KERNEL);
		if (!hash) {
			mutex_unlock(&ctx->uring_lock);
			return ERR_PTR(-ENOMEM);
		}
		refcount_set(&hash->refs, 1);
		init_waitqueue_head(&hash->wait);
		ctx->hash_map = hash;
	}
	mutex_unlock(&ctx->uring_lock);

	data.hash = hash;
	data.task = task;
	data.free_work = io_wq_free_work;
	data.do_work = io_wq_submit_work;

	/* Do QD, or 4 * CPUS, whatever is smallest */
	concurrency = min(ctx->sq_entries, 4 * num_online_cpus());

	return io_wq_create(concurrency, &data);
}

/*
 This function, __io_uring_free, appears to be responsible for freeing resources associated with an io_uring task context (tctx) when a task (tsk) is being cleaned up.
 It checks for potential errors or inconsistencies in the tctx state, such as unexpected entries in an xarray (xa) or non-NULL pointers to a workqueue (io_wq) or cached references (cached_refs), and logs warnings if any are found.
 Finally, it destroys a percpu counter (inflight), frees the tctx memory, and sets the io_uring pointer in the task structure to NULL.
*/
void __io_uring_free(struct task_struct *tsk)
{
	struct io_uring_task *tctx = tsk->io_uring;
	struct io_tctx_node *node;
	unsigned long index;

	/*
	 * Fault injection forcing allocation errors in the xa_store() path
	 * can lead to xa_empty() returning false, even though no actual
	 * node is stored in the xarray. Until that gets sorted out, attempt
	 * an iteration here and warn if any entries are found.
	 */
	xa_for_each(&tctx->xa, index, node) {
		WARN_ON_ONCE(1);
		break;
	}
	WARN_ON_ONCE(tctx->io_wq);
	WARN_ON_ONCE(tctx->cached_refs);

	percpu_counter_destroy(&tctx->inflight);
	kfree(tctx);
	tsk->io_uring = NULL;
}

/*
 This function, io_uring_alloc_task_context, allocates memory for a task context (tctx) associated with an io_uring context (ctx) for a given task (tsk). 
 It initializes various fields in the tctx structure, including a percpu counter for tracking inflight requests and a workqueue for offloading I/O operations. 
 If any allocation or initialization fails, it cleans up and returns an error code.
*/
__cold int io_uring_alloc_task_context(struct task_struct *task,
				       struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx;
	int ret;

	tctx = kzalloc(sizeof(*tctx), GFP_KERNEL);
	if (unlikely(!tctx))
		return -ENOMEM;

	ret = percpu_counter_init(&tctx->inflight, 0, GFP_KERNEL);
	if (unlikely(ret)) {
		kfree(tctx);
		return ret;
	}

	tctx->io_wq = io_init_wq_offload(ctx, task);
	if (IS_ERR(tctx->io_wq)) {
		ret = PTR_ERR(tctx->io_wq);
		percpu_counter_destroy(&tctx->inflight);
		kfree(tctx);
		return ret;
	}

	tctx->task = task;
	xa_init(&tctx->xa);
	init_waitqueue_head(&tctx->wait);
	atomic_set(&tctx->in_cancel, 0);
	atomic_set(&tctx->inflight_tracked, 0);
	task->io_uring = tctx;
	init_llist_head(&tctx->task_list);
	init_task_work(&tctx->task_work, tctx_task_work);
	return 0;
}

/*
 This function adds a task context node to an io_uring context. If the task context doesn't exist, it allocates one and sets up its io worker queue limits. Then, it checks if a node for the given io_uring context already exists in the task's xarray. 
 If not, it creates a new node, stores it in the xarray, and adds it to the io_uring context's task list.
*/
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_tctx_node *node;
	int ret;

	if (unlikely(!tctx)) {
		ret = io_uring_alloc_task_context(current, ctx);
		if (unlikely(ret))
			return ret;

		tctx = current->io_uring;
		if (ctx->iowq_limits_set) {
			unsigned int limits[2] = { ctx->iowq_limits[0],
						   ctx->iowq_limits[1], };

			ret = io_wq_max_workers(tctx->io_wq, limits);
			if (ret)
				return ret;
		}
	}
	if (!xa_load(&tctx->xa, (unsigned long)ctx)) {
		node = kmalloc(sizeof(*node), GFP_KERNEL);
		if (!node)
			return -ENOMEM;
		node->ctx = ctx;
		node->task = current;

		ret = xa_err(xa_store(&tctx->xa, (unsigned long)ctx,
					node, GFP_KERNEL));
		if (ret) {
			kfree(node);
			return ret;
		}

		mutex_lock(&ctx->uring_lock);
		list_add(&node->ctx_node, &ctx->tctx_list);
		mutex_unlock(&ctx->uring_lock);
	}
	return 0;
}

/*
 This function adds a task context node to an io_uring context from the submit path. 
 It checks if the current task is the submitter and if not, returns an error. 
 If the task context node is successfully added, it updates the last field of the io_uring task structure.
*/
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx)
{
	int ret;

	if (ctx->flags & IORING_SETUP_SINGLE_ISSUER
	    && ctx->submitter_task != current)
		return -EEXIST;

	ret = __io_uring_add_tctx_node(ctx);
	if (ret)
		return ret;

	current->io_uring->last = ctx;
	return 0;
}

/*
 * Remove this io_uring_file -> task mapping.
 */
__cold void io_uring_del_tctx_node(unsigned long index)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_tctx_node *node;

	if (!tctx)
		return;
	node = xa_erase(&tctx->xa, index);
	if (!node)
		return;

	WARN_ON_ONCE(current != node->task);
	WARN_ON_ONCE(list_empty(&node->ctx_node));

	mutex_lock(&node->ctx->uring_lock);
	list_del(&node->ctx_node);
	mutex_unlock(&node->ctx->uring_lock);

	if (tctx->last == node->ctx)
		tctx->last = NULL;
	kfree(node);
}

/*
 This function cleans up the task context (tctx) associated with the current task. 
 It iterates through the xarray of task context nodes, removing each one and freeing its memory. 
 If the task context has an associated workqueue (io_wq), it releases it and sets the pointer to NULL.
*/
__cold void io_uring_clean_tctx(struct io_uring_task *tctx)
{
	struct io_wq *wq = tctx->io_wq;
	struct io_tctx_node *node;
	unsigned long index;

	xa_for_each(&tctx->xa, index, node) {
		io_uring_del_tctx_node(index);
		cond_resched();
	}
	if (wq) {
		/*
		 * Must be after io_uring_del_tctx_node() (removes nodes under
		 * uring_lock) to avoid race with io_uring_try_cancel_iowq().
		 */
		io_wq_put_and_exit(wq);
		tctx->io_wq = NULL;
	}
}

/*
 This function unregisters the ring file descriptors associated with the current task's io_uring context. 
 It iterates through the registered ring file descriptors and releases each one, setting the corresponding pointer to NULL.
*/
void io_uring_unreg_ringfd(void)
{
	struct io_uring_task *tctx = current->io_uring;
	int i;

	for (i = 0; i < IO_RINGFD_REG_MAX; i++) {
		if (tctx->registered_rings[i]) {
			fput(tctx->registered_rings[i]);
			tctx->registered_rings[i] = NULL;
		}
	}
}

/*
 This function adds a registered file to the task context's (tctx) array of registered ring file descriptors (registered_rings). 
 It searches for an available slot in the array between start and end indices, and if found, assigns the file to that slot and returns the index. If all slots are occupied, it returns -EBUSY.
*/
int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file,
				     int start, int end)
{
	int offset;
	for (offset = start; offset < end; offset++) {
		offset = array_index_nospec(offset, IO_RINGFD_REG_MAX);
		if (tctx->registered_rings[offset])
			continue;

		tctx->registered_rings[offset] = file;
		return offset;
	}
	return -EBUSY;
}

/*
 This function adds a registered file descriptor (fd) to the task context's (tctx) array of registered ring file descriptors (registered_rings). 
 It first retrieves the file structure associated with the fd, checks if it is valid and supports io_uring operations, and then calls io_ring_add_registered_file to add it to the array. 
 If successful, it returns the index of the added file; otherwise, it returns an error code.
*/
static int io_ring_add_registered_fd(struct io_uring_task *tctx, int fd,
				     int start, int end)
{
	struct file *file;
	int offset;

	file = fget(fd);
	if (!file) {
		return -EBADF;
	} else if (!io_is_uring_fops(file)) {
		fput(file);
		return -EOPNOTSUPP;
	}
	offset = io_ring_add_registered_file(tctx, file, start, end);
	if (offset < 0)
		fput(file);
	return offset;
}

/*
 * Register a ring fd to avoid fdget/fdput for each io_uring_enter()
 * invocation. User passes in an array of struct io_uring_rsrc_update
 * with ->data set to the ring_fd, and ->offset given for the desired
 * index. If no index is desired, application may set ->offset == -1U
 * and we'll find an available index. Returns number of entries
 * successfully processed, or < 0 on error if none were processed.
 */
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
		       unsigned nr_args)
{
	struct io_uring_rsrc_update __user *arg = __arg;
	struct io_uring_rsrc_update reg;
	struct io_uring_task *tctx;
	int ret, i;

	if (!nr_args || nr_args > IO_RINGFD_REG_MAX)
		return -EINVAL;

	mutex_unlock(&ctx->uring_lock);
	ret = __io_uring_add_tctx_node(ctx);
	mutex_lock(&ctx->uring_lock);
	if (ret)
		return ret;

	tctx = current->io_uring;
	for (i = 0; i < nr_args; i++) {
		int start, end;

		if (copy_from_user(&reg, &arg[i], sizeof(reg))) {
			ret = -EFAULT;
			break;
		}

		if (reg.resv) {
			ret = -EINVAL;
			break;
		}

		if (reg.offset == -1U) {
			start = 0;
			end = IO_RINGFD_REG_MAX;
		} else {
			if (reg.offset >= IO_RINGFD_REG_MAX) {
				ret = -EINVAL;
				break;
			}
			start = reg.offset;
			end = start + 1;
		}

		ret = io_ring_add_registered_fd(tctx, reg.data, start, end);
		if (ret < 0)
			break;

		reg.offset = ret;
		if (copy_to_user(&arg[i], &reg, sizeof(reg))) {
			fput(tctx->registered_rings[reg.offset]);
			tctx->registered_rings[reg.offset] = NULL;
			ret = -EFAULT;
			break;
		}
	}

	return i ? i : ret;
}

/*
 Unregister a ring fd. User passes in an array of struct io_uring_rsrc_update
 with ->data set to the ring_fd, and ->offset given for the desired index.
 Returns number of entries successfully processed, or < 0 on error if none
 were processed.
 */
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
			 unsigned nr_args)
{
	struct io_uring_rsrc_update __user *arg = __arg;
	struct io_uring_task *tctx = current->io_uring;
	struct io_uring_rsrc_update reg;
	int ret = 0, i;

	if (!nr_args || nr_args > IO_RINGFD_REG_MAX)
		return -EINVAL;
	if (!tctx)
		return 0;

	for (i = 0; i < nr_args; i++) {
		if (copy_from_user(&reg, &arg[i], sizeof(reg))) {
			ret = -EFAULT;
			break;
		}
		if (reg.resv || reg.data || reg.offset >= IO_RINGFD_REG_MAX) {
			ret = -EINVAL;
			break;
		}

		reg.offset = array_index_nospec(reg.offset, IO_RINGFD_REG_MAX);
		if (tctx->registered_rings[reg.offset]) {
			fput(tctx->registered_rings[reg.offset]);
			tctx->registered_rings[reg.offset] = NULL;
		}
	}

	return i ? i : ret;
}
