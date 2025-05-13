// SPDX-License-Identifier: GPL-2.0
/*
 * Basic worker thread pool for io_uring
 *
 * Copyright (C) 2019 Jens Axboe
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/rculist_nulls.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/task_work.h>
#include <linux/audit.h>
#include <linux/mmu_context.h>
#include <uapi/linux/io_uring.h>

#include "io-wq.h"
#include "slist.h"
#include "io_uring.h"

#define WORKER_IDLE_TIMEOUT	(5 * HZ)
#define WORKER_INIT_LIMIT	3

enum {
	IO_WORKER_F_UP		= 0,	/* up and active */
	IO_WORKER_F_RUNNING	= 1,	/* account as running */
	IO_WORKER_F_FREE	= 2,	/* worker on free list */
};

enum {
	IO_WQ_BIT_EXIT		= 0,	/* wq exiting */
};

enum {
	IO_ACCT_STALLED_BIT	= 0,	/* stalled on hash */
};

/*
 * One for each thread in a wq pool
 */
struct io_worker {
	refcount_t ref;
	unsigned long flags;
	struct hlist_nulls_node nulls_node;
	struct list_head all_list;
	struct task_struct *task;
	struct io_wq *wq;
	struct io_wq_acct *acct;

	struct io_wq_work *cur_work;
	raw_spinlock_t lock;

	struct completion ref_done;

	unsigned long create_state;
	struct callback_head create_work;
	int init_retries;

	union {
		struct rcu_head rcu;
		struct delayed_work work;
	};
};

#if BITS_PER_LONG == 64
#define IO_WQ_HASH_ORDER	6
#else
#define IO_WQ_HASH_ORDER	5
#endif

#define IO_WQ_NR_HASH_BUCKETS	(1u << IO_WQ_HASH_ORDER)

struct io_wq_acct {
	/**
	 * Protects access to the worker lists.
	 */
	raw_spinlock_t workers_lock;

	unsigned nr_workers;
	unsigned max_workers;
	atomic_t nr_running;

	/**
	 * The list of free workers.  Protected by #workers_lock
	 * (write) and RCU (read).
	 */
	struct hlist_nulls_head free_list;

	/**
	 * The list of all workers.  Protected by #workers_lock
	 * (write) and RCU (read).
	 */
	struct list_head all_list;

	raw_spinlock_t lock;
	struct io_wq_work_list work_list;
	unsigned long flags;
};

enum {
	IO_WQ_ACCT_BOUND,
	IO_WQ_ACCT_UNBOUND,
	IO_WQ_ACCT_NR,
};

/*
 * Per io_wq state
  */
struct io_wq {
	unsigned long state;

	free_work_fn *free_work;
	io_wq_work_fn *do_work;

	struct io_wq_hash *hash;

	atomic_t worker_refs;
	struct completion worker_done;

	struct hlist_node cpuhp_node;

	struct task_struct *task;

	struct io_wq_acct acct[IO_WQ_ACCT_NR];

	struct wait_queue_entry wait;

	struct io_wq_work *hash_tail[IO_WQ_NR_HASH_BUCKETS];

	cpumask_var_t cpu_mask;
};

static enum cpuhp_state io_wq_online;

struct io_cb_cancel_data {
	work_cancel_fn *fn;
	void *data;
	int nr_running;
	int nr_pending;
	bool cancel_all;
};

static bool create_io_worker(struct io_wq *wq, struct io_wq_acct *acct);
static void io_wq_dec_running(struct io_worker *worker);
static bool io_acct_cancel_pending_work(struct io_wq *wq,
					struct io_wq_acct *acct,
					struct io_cb_cancel_data *match);
static void create_worker_cb(struct callback_head *cb);
static void io_wq_cancel_tw_create(struct io_wq *wq);

static bool io_worker_get(struct io_worker *worker)
{
	return refcount_inc_not_zero(&worker->ref);
}

static void io_worker_release(struct io_worker *worker)
{
	if (refcount_dec_and_test(&worker->ref))
		complete(&worker->ref_done);
}

static inline struct io_wq_acct *io_get_acct(struct io_wq *wq, bool bound)
{
	return &wq->acct[bound ? IO_WQ_ACCT_BOUND : IO_WQ_ACCT_UNBOUND];
}

static inline struct io_wq_acct *io_work_get_acct(struct io_wq *wq,
						  unsigned int work_flags)
{
	return io_get_acct(wq, !(work_flags & IO_WQ_WORK_UNBOUND));
}

static inline struct io_wq_acct *io_wq_get_acct(struct io_worker *worker)
{
	return worker->acct;
}

/*
io_worker_ref_put: This function decrements the reference count (worker_refs) for the io_wq structure. If the reference count reaches zero, it signals the completion of the worker_done event using complete().
Purpose: Ensures proper cleanup of the workqueue when all workers have finished their tasks.
*/
static void io_worker_ref_put(struct io_wq *wq)
{
	if (atomic_dec_and_test(&wq->worker_refs))
		complete(&wq->worker_done);
}

/*
io_wq_worker_stopped: Checks if the current worker has been stopped. It retrieves the worker_private field of the current task and verifies if the IO_WQ_BIT_EXIT flag is set in the worker's state.
Purpose: Determines whether a worker is in the process of exiting, ensuring that no further tasks are assigned to it.
*/
bool io_wq_worker_stopped(void)
{
	struct io_worker *worker = current->worker_private;

	if (WARN_ON_ONCE(!io_wq_current_is_worker()))
		return true;

	return test_bit(IO_WQ_BIT_EXIT, &worker->wq->state);
}

/*
io_worker_cancel_cb: Cancels a worker by performing the following steps:
Decrements the number of running workers (nr_running) in the associated accounting structure (io_wq_acct).
Updates the worker count (nr_workers) under a spinlock to ensure thread safety.
Releases the worker reference and clears its creation state.
Calls io_worker_release to finalize the worker's cleanup.
Purpose: Handles the safe cancellation of a worker, ensuring proper accounting and cleanup.

*/
static void io_worker_cancel_cb(struct io_worker *worker)
{
	struct io_wq_acct *acct = io_wq_get_acct(worker);
	struct io_wq *wq = worker->wq;

	atomic_dec(&acct->nr_running);
	raw_spin_lock(&acct->workers_lock);
	acct->nr_workers--;
	raw_spin_unlock(&acct->workers_lock);
	io_worker_ref_put(wq);
	clear_bit_unlock(0, &worker->create_state);
	io_worker_release(worker);
}

/*
io_task_worker_match: Matches a task's callback (callback_head) with a specific worker. It checks if the callback function is create_worker_cb and verifies that the callback belongs to the given worker.
Purpose: Identifies tasks associated with a specific worker, enabling targeted cancellation or processing.
*/
static bool io_task_worker_match(struct callback_head *cb, void *data)
{
	struct io_worker *worker;

	if (cb->func != create_worker_cb)
		return false;
	worker = container_of(cb, struct io_worker, create_work);
	return worker == data;
}

/*
io_worker_exit: Handles the complete exit process for a worker:
Cancels any pending task work associated with the worker using task_work_cancel_match.
Waits for the worker's references to be released (ref_done).
Removes the worker from the free list and all workers list under a spinlock.
Decrements the running worker count and clears the worker_private field of the current task to prevent further interactions with the exiting worker.
Frees the worker's memory using kfree_rcu and decrements the workqueue's reference count.
Calls do_exit(0) to terminate the worker thread.
Purpose: Ensures a clean and safe shutdown of a worker, releasing all associated resources.
*/
static void io_worker_exit(struct io_worker *worker)
{
	struct io_wq *wq = worker->wq;
	struct io_wq_acct *acct = io_wq_get_acct(worker);

	while (1) {
		struct callback_head *cb = task_work_cancel_match(wq->task,
						io_task_worker_match, worker);

		if (!cb)
			break;
		io_worker_cancel_cb(worker);
	}

	io_worker_release(worker);
	wait_for_completion(&worker->ref_done);

	raw_spin_lock(&acct->workers_lock);
	if (test_bit(IO_WORKER_F_FREE, &worker->flags))
		hlist_nulls_del_rcu(&worker->nulls_node);
	list_del_rcu(&worker->all_list);
	raw_spin_unlock(&acct->workers_lock);
	io_wq_dec_running(worker);
	/*
	 * this worker is a goner, clear ->worker_private to avoid any
	 * inc/dec running calls that could happen as part of exit from
	 * touching 'worker'.
	 */
	current->worker_private = NULL;

	kfree_rcu(worker, rcu);
	io_worker_ref_put(wq);
	do_exit(0);
}

/*
__io_acct_run_queue: Checks if there is work to process in the accounting structure (io_wq_acct). It verifies that the IO_ACCT_STALLED_BIT flag is not set and that the work list is not empty.

Purpose: Determines if the workqueue is ready to process tasks.
*/
static inline bool __io_acct_run_queue(struct io_wq_acct *acct)
{
	return !test_bit(IO_ACCT_STALLED_BIT, &acct->flags) &&
		!wq_list_empty(&acct->work_list);
}

/*
 * If there's work to do, returns true with acct->lock acquired. If not,
 * returns false with no lock held.
 */
 /*
 io_acct_run_queue: Acquires the lock for the accounting structure and checks if there is work to process using __io_acct_run_queue. If no work is found, it releases the lock.

Purpose: Safely checks for pending work while ensuring proper synchronization.
 */
static inline bool io_acct_run_queue(struct io_wq_acct *acct)
	__acquires(&acct->lock)
{
	raw_spin_lock(&acct->lock);
	if (__io_acct_run_queue(acct))
		return true;

	raw_spin_unlock(&acct->lock);
	return false;
}

/*
 * Check head of free list for an available worker. If one isn't available,
 * caller must create one.
 */
 /*
 io_acct_activate_free_worker: Attempts to activate an idle worker from the free list:
Iterates over the free list (free_list) to find an idle worker.
If a worker is found and is not in the process of exiting, it wakes up the worker's task and releases the worker reference.
If no suitable worker is found, the function returns false, indicating that a new worker may need to be created.
Purpose: Efficiently reuses idle workers to handle new tasks, minimizing the overhead of creating new worker threads.
 */
static bool io_acct_activate_free_worker(struct io_wq_acct *acct)
	__must_hold(RCU)
{
	struct hlist_nulls_node *n;
	struct io_worker *worker;

	/*
	 * Iterate free_list and see if we can find an idle worker to
	 * activate. If a given worker is on the free_list but in the process
	 * of exiting, keep trying.
	 */
	hlist_nulls_for_each_entry_rcu(worker, n, &acct->free_list, nulls_node) {
		if (!io_worker_get(worker))
			continue;
		/*
		 * If the worker is already running, it's either already
		 * starting work or finishing work. In either case, if it does
		 * to go sleep, we'll kick off a new task for this work anyway.
		 */
		wake_up_process(worker->task);
		io_worker_release(worker);
		return true;
	}

	return false;
}

/*
 * We need a worker. If we find a free one, we're good. If not, and we're
 * below the max number of workers, create one.
 */
 /*
 io_wq_create_worker: This function creates a new worker for the io_wq if the number of workers (nr_workers) is below the maximum allowed (max_workers). It increments the worker count and running worker count (nr_running) and calls create_io_worker to initialize the worker.

Purpose: Dynamically adds workers to handle tasks, ensuring the workqueue can scale based on workload demands.
 */
static bool io_wq_create_worker(struct io_wq *wq, struct io_wq_acct *acct)
{
	/*
	 * Most likely an attempt to queue unbounded work on an io_wq that
	 * wasn't setup with any unbounded workers.
	 */
	if (unlikely(!acct->max_workers))
		pr_warn_once("io-wq is not configured for unbound workers");

	raw_spin_lock(&acct->workers_lock);
	if (acct->nr_workers >= acct->max_workers) {
		raw_spin_unlock(&acct->workers_lock);
		return true;
	}
	acct->nr_workers++;
	raw_spin_unlock(&acct->workers_lock);
	atomic_inc(&acct->nr_running);
	atomic_inc(&wq->worker_refs);
	return create_io_worker(wq, acct);
}

/*
io_wq_inc_running: Increments the count of running workers (nr_running) for the associated accounting structure (io_wq_acct).

Purpose: Tracks the number of active workers processing tasks.
*/
static void io_wq_inc_running(struct io_worker *worker)
{
	struct io_wq_acct *acct = io_wq_get_acct(worker);

	atomic_inc(&acct->nr_running);
}

/*
create_worker_cb: A callback function used to create a new worker. It checks if the number of workers is below the maximum limit and creates a new worker if needed. If not, it decrements the running worker count and releases the worker reference.

Purpose: Handles worker creation in response to specific events or conditions.
*/
static void create_worker_cb(struct callback_head *cb)
{
	struct io_worker *worker;
	struct io_wq *wq;

	struct io_wq_acct *acct;
	bool do_create = false;

	worker = container_of(cb, struct io_worker, create_work);
	wq = worker->wq;
	acct = worker->acct;
	raw_spin_lock(&acct->workers_lock);

	if (acct->nr_workers < acct->max_workers) {
		acct->nr_workers++;
		do_create = true;
	}
	raw_spin_unlock(&acct->workers_lock);
	if (do_create) {
		create_io_worker(wq, acct);
	} else {
		atomic_dec(&acct->nr_running);
		io_worker_ref_put(wq);
	}
	clear_bit_unlock(0, &worker->create_state);
	io_worker_release(worker);
}

/*
io_queue_worker_create: Queues a task to create a new worker. It ensures that the worker is not in the process of exiting and that the create_state is properly managed to avoid duplicate creation tasks.

Purpose: Safely schedules worker creation tasks while maintaining synchronization.
*/
static bool io_queue_worker_create(struct io_worker *worker,
				   struct io_wq_acct *acct,
				   task_work_func_t func)
{
	struct io_wq *wq = worker->wq;

	/* raced with exit, just ignore create call */
	if (test_bit(IO_WQ_BIT_EXIT, &wq->state))
		goto fail;
	if (!io_worker_get(worker))
		goto fail;
	/*
	 * create_state manages ownership of create_work/index. We should
	 * only need one entry per worker, as the worker going to sleep
	 * will trigger the condition, and waking will clear it once it
	 * runs the task_work.
	 */
	if (test_bit(0, &worker->create_state) ||
	    test_and_set_bit_lock(0, &worker->create_state))
		goto fail_release;

	atomic_inc(&wq->worker_refs);
	init_task_work(&worker->create_work, func);
	if (!task_work_add(wq->task, &worker->create_work, TWA_SIGNAL)) {
		/*
		 * EXIT may have been set after checking it above, check after
		 * adding the task_work and remove any creation item if it is
		 * now set. wq exit does that too, but we can have added this
		 * work item after we canceled in io_wq_exit_workers().
		 */
		if (test_bit(IO_WQ_BIT_EXIT, &wq->state))
			io_wq_cancel_tw_create(wq);
		io_worker_ref_put(wq);
		return true;
	}
	io_worker_ref_put(wq);
	clear_bit_unlock(0, &worker->create_state);
fail_release:
	io_worker_release(worker);
fail:
	atomic_dec(&acct->nr_running);
	io_worker_ref_put(wq);
	return false;
}

/*
io_wq_dec_running: Decrements the count of running workers. If no workers are running and there is pending work in the queue, it schedules the creation of a new worker.

Purpose: Ensures that the workqueue remains responsive by creating new workers when needed.
*/
static void io_wq_dec_running(struct io_worker *worker)
{
	struct io_wq_acct *acct = io_wq_get_acct(worker);
	struct io_wq *wq = worker->wq;

	if (!test_bit(IO_WORKER_F_UP, &worker->flags))
		return;

	if (!atomic_dec_and_test(&acct->nr_running))
		return;
	if (!io_acct_run_queue(acct))
		return;

	raw_spin_unlock(&acct->lock);
	atomic_inc(&acct->nr_running);
	atomic_inc(&wq->worker_refs);
	io_queue_worker_create(worker, acct, create_worker_cb);
}

/*
 * Worker will start processing some work. Move it to the busy list, if
 * it's currently on the freelist
 */
 /*
 __io_worker_busy: Moves a worker from the free list to the busy state when it starts processing work. It removes the worker from the free list and clears the IO_WORKER_F_FREE flag.

Purpose: Tracks workers that are actively processing tasks.
 */
static void __io_worker_busy(struct io_wq_acct *acct, struct io_worker *worker)
{
	if (test_bit(IO_WORKER_F_FREE, &worker->flags)) {
		clear_bit(IO_WORKER_F_FREE, &worker->flags);
		raw_spin_lock(&acct->workers_lock);
		hlist_nulls_del_init_rcu(&worker->nulls_node);
		raw_spin_unlock(&acct->workers_lock);
	}
}

/*
 * No work, worker going to sleep. Move to freelist.
 */
 /*
 __io_worker_idle: Moves a worker to the free list when it has no work to process. It sets the IO_WORKER_F_FREE flag and adds the worker to the free list.

Purpose: Manages idle workers, making them available for future tasks.
 */
static void __io_worker_idle(struct io_wq_acct *acct, struct io_worker *worker)
	__must_hold(acct->workers_lock)
{
	if (!test_bit(IO_WORKER_F_FREE, &worker->flags)) {
		set_bit(IO_WORKER_F_FREE, &worker->flags);
		hlist_nulls_add_head_rcu(&worker->nulls_node, &acct->free_list);
	}
}

/*
__io_get_work_hash and io_get_work_hash: Extract the hash value from the work's flags. This hash is used to group and manage work items with similar characteristics.

Purpose: Enables efficient scheduling and conflict resolution for hashed work items.
*/
static inline unsigned int __io_get_work_hash(unsigned int work_flags)
{
	return work_flags >> IO_WQ_HASH_SHIFT;
}

static inline unsigned int io_get_work_hash(struct io_wq_work *work)
{
	return __io_get_work_hash(atomic_read(&work->flags));
}

/*
io_wait_on_hash: Waits for a specific hash to become available. If the hash is not currently being processed, it sets the task state to running and removes the wait entry.

Purpose: Ensures that hashed work items are processed in a synchronized manner.
*/
static bool io_wait_on_hash(struct io_wq *wq, unsigned int hash)
{
	bool ret = false;

	spin_lock_irq(&wq->hash->wait.lock);
	if (list_empty(&wq->wait.entry)) {
		__add_wait_queue(&wq->hash->wait, &wq->wait);
		if (!test_bit(hash, &wq->hash->map)) {
			__set_current_state(TASK_RUNNING);
			list_del_init(&wq->wait.entry);
			ret = true;
		}
	}
	spin_unlock_irq(&wq->hash->wait.lock);
	return ret;
}

/*
io_get_next_work: Retrieves the next work item from the work list. It prioritizes non-hashed work, but if hashed work is encountered, it ensures that only one worker processes a specific hash at a time. If all work is stalled due to hashing conflicts, it waits for the hash to become available.

Purpose: Implements fair and efficient scheduling of work items, resolving conflicts for hashed tasks.
*/
static struct io_wq_work *io_get_next_work(struct io_wq_acct *acct,
					   struct io_wq *wq)
	__must_hold(acct->lock)
{
	struct io_wq_work_node *node, *prev;
	struct io_wq_work *work, *tail;
	unsigned int stall_hash = -1U;

	wq_list_for_each(node, prev, &acct->work_list) {
		unsigned int work_flags;
		unsigned int hash;

		work = container_of(node, struct io_wq_work, list);

		/* not hashed, can run anytime */
		work_flags = atomic_read(&work->flags);
		if (!__io_wq_is_hashed(work_flags)) {
			wq_list_del(&acct->work_list, node, prev);
			return work;
		}

		hash = __io_get_work_hash(work_flags);
		/* all items with this hash lie in [work, tail] */
		tail = wq->hash_tail[hash];

		/* hashed, can run if not already running */
		if (!test_and_set_bit(hash, &wq->hash->map)) {
			wq->hash_tail[hash] = NULL;
			wq_list_cut(&acct->work_list, &tail->list, prev);
			return work;
		}
		if (stall_hash == -1U)
			stall_hash = hash;
		/* fast forward to a next hash, for-each will fix up @prev */
		node = &tail->list;
	}

	if (stall_hash != -1U) {
		bool unstalled;

		/*
		 * Set this before dropping the lock to avoid racing with new
		 * work being added and clearing the stalled bit.
		 */
		set_bit(IO_ACCT_STALLED_BIT, &acct->flags);
		raw_spin_unlock(&acct->lock);
		unstalled = io_wait_on_hash(wq, stall_hash);
		raw_spin_lock(&acct->lock);
		if (unstalled) {
			clear_bit(IO_ACCT_STALLED_BIT, &acct->flags);
			if (wq_has_sleeper(&wq->hash->wait))
				wake_up(&wq->hash->wait);
		}
	}

	return NULL;
}

/*
io_assign_current_work: This function assigns a work item to a worker. If a work item is provided, it first processes any pending task work (io_run_task_work) and allows the scheduler to reschedule if necessary (cond_resched). The function then updates the worker's cur_work field under a spinlock to ensure thread safety.
Purpose: Safely assigns a work item to a worker while maintaining synchronization.
*/
static void io_assign_current_work(struct io_worker *worker,
				   struct io_wq_work *work)
{
	if (work) {
		io_run_task_work();
		cond_resched();
	}

	raw_spin_lock(&worker->lock);
	worker->cur_work = work;
	raw_spin_unlock(&worker->lock);
}

/*
 * Called with acct->lock held, drops it before returning
 */
 /*
 io_worker_handle_work: This function processes work items for a worker. It retrieves the next work item using io_get_next_work and marks the worker as busy (__io_worker_busy). The function handles dependent or linked work items, ensuring that all related tasks are processed together. If the work item is hashed, it manages hash-based synchronization to avoid conflicts.

Purpose: Efficiently processes work items, including handling dependencies and resolving hashing conflicts.
 */
static void io_worker_handle_work(struct io_wq_acct *acct,
				  struct io_worker *worker)
	__releases(&acct->lock)
{
	struct io_wq *wq = worker->wq;
	bool do_kill = test_bit(IO_WQ_BIT_EXIT, &wq->state);

	do {
		struct io_wq_work *work;

		/*
		 * If we got some work, mark us as busy. If we didn't, but
		 * the list isn't empty, it means we stalled on hashed work.
		 * Mark us stalled so we don't keep looking for work when we
		 * can't make progress, any work completion or insertion will
		 * clear the stalled flag.
		 */
		work = io_get_next_work(acct, wq);
		if (work) {
			/*
			 * Make sure cancelation can find this, even before
			 * it becomes the active work. That avoids a window
			 * where the work has been removed from our general
			 * work list, but isn't yet discoverable as the
			 * current work item for this worker.
			 */
			raw_spin_lock(&worker->lock);
			worker->cur_work = work;
			raw_spin_unlock(&worker->lock);
		}

		raw_spin_unlock(&acct->lock);

		if (!work)
			break;

		__io_worker_busy(acct, worker);

		io_assign_current_work(worker, work);
		__set_current_state(TASK_RUNNING);

		/* handle a whole dependent link */
		do {
			struct io_wq_work *next_hashed, *linked;
			unsigned int work_flags = atomic_read(&work->flags);
			unsigned int hash = __io_wq_is_hashed(work_flags)
				? __io_get_work_hash(work_flags)
				: -1U;

			next_hashed = wq_next_work(work);

			if (do_kill &&
			    (work_flags & IO_WQ_WORK_UNBOUND))
				atomic_or(IO_WQ_WORK_CANCEL, &work->flags);
			wq->do_work(work);
			io_assign_current_work(worker, NULL);

			linked = wq->free_work(work);
			work = next_hashed;
			if (!work && linked && !io_wq_is_hashed(linked)) {
				work = linked;
				linked = NULL;
			}
			io_assign_current_work(worker, work);
			if (linked)
				io_wq_enqueue(wq, linked);

			if (hash != -1U && !next_hashed) {
				/* serialize hash clear with wake_up() */
				spin_lock_irq(&wq->hash->wait.lock);
				clear_bit(hash, &wq->hash->map);
				clear_bit(IO_ACCT_STALLED_BIT, &acct->flags);
				spin_unlock_irq(&wq->hash->wait.lock);
				if (wq_has_sleeper(&wq->hash->wait))
					wake_up(&wq->hash->wait);
			}
		} while (work);

		if (!__io_acct_run_queue(acct))
			break;
		raw_spin_lock(&acct->lock);
	} while (1);
}

/*
io_wq_worker: This is the main function executed by worker threads. It continuously checks for work to process and handles it using io_worker_handle_work. If no work is available, the worker transitions to an idle state (__io_worker_idle) and waits for new tasks or a timeout.
Timeout Handling: If the worker times out while idle, it checks whether it should exit (e.g., if it is not the last worker or its CPU affinity has changed).
Signal Handling: The function handles signals sent to the worker, ensuring that it can exit cleanly if required.
Purpose: Implements the main loop for worker threads, managing their lifecycle and ensuring responsiveness to new tasks.
*/
static int io_wq_worker(void *data)
{
	struct io_worker *worker = data;
	struct io_wq_acct *acct = io_wq_get_acct(worker);
	struct io_wq *wq = worker->wq;
	bool exit_mask = false, last_timeout = false;
	char buf[TASK_COMM_LEN] = {};

	set_mask_bits(&worker->flags, 0,
		      BIT(IO_WORKER_F_UP) | BIT(IO_WORKER_F_RUNNING));

	snprintf(buf, sizeof(buf), "iou-wrk-%d", wq->task->pid);
	set_task_comm(current, buf);

	while (!test_bit(IO_WQ_BIT_EXIT, &wq->state)) {
		long ret;

		set_current_state(TASK_INTERRUPTIBLE);

		/*
		 * If we have work to do, io_acct_run_queue() returns with
		 * the acct->lock held. If not, it will drop it.
		 */
		while (io_acct_run_queue(acct))
			io_worker_handle_work(acct, worker);

		raw_spin_lock(&acct->workers_lock);
		/*
		 * Last sleep timed out. Exit if we're not the last worker,
		 * or if someone modified our affinity.
		 */
		if (last_timeout && (exit_mask || acct->nr_workers > 1)) {
			acct->nr_workers--;
			raw_spin_unlock(&acct->workers_lock);
			__set_current_state(TASK_RUNNING);
			break;
		}
		last_timeout = false;
		__io_worker_idle(acct, worker);
		raw_spin_unlock(&acct->workers_lock);
		if (io_run_task_work())
			continue;
		ret = schedule_timeout(WORKER_IDLE_TIMEOUT);
		if (signal_pending(current)) {
			struct ksignal ksig;

			if (!get_signal(&ksig))
				continue;
			break;
		}
		if (!ret) {
			last_timeout = true;
			exit_mask = !cpumask_test_cpu(raw_smp_processor_id(),
							wq->cpu_mask);
		}
	}

	if (test_bit(IO_WQ_BIT_EXIT, &wq->state) && io_acct_run_queue(acct))
		io_worker_handle_work(acct, worker);

	io_worker_exit(worker);
	return 0;
}

/*
 * Called when a worker is scheduled in. Mark us as currently running.
 */
 /*
 io_wq_worker_running: Called when a worker is scheduled in. It marks the worker as running by setting the IO_WORKER_F_RUNNING flag and increments the count of running workers (io_wq_inc_running).

Purpose: Tracks workers that are actively running and processing tasks.
 */
void io_wq_worker_running(struct task_struct *tsk)
{
	struct io_worker *worker = tsk->worker_private;

	if (!worker)
		return;
	if (!test_bit(IO_WORKER_F_UP, &worker->flags))
		return;
	if (test_bit(IO_WORKER_F_RUNNING, &worker->flags))
		return;
	set_bit(IO_WORKER_F_RUNNING, &worker->flags);
	io_wq_inc_running(worker);
}

/*
 * Called when worker is going to sleep. If there are no workers currently
 * running and we have work pending, wake up a free one or create a new one.
 */
 /*
 io_wq_worker_sleeping: Called when a worker is about to sleep. It clears the IO_WORKER_F_RUNNING flag and decrements the count of running workers (io_wq_dec_running). If no workers are running and there is pending work, it wakes up an idle worker or creates a new one.

Purpose: Manages transitions between active and idle states for workers, ensuring that the workqueue remains responsive.
 */
void io_wq_worker_sleeping(struct task_struct *tsk)
{
	struct io_worker *worker = tsk->worker_private;

	if (!worker)
		return;
	if (!test_bit(IO_WORKER_F_UP, &worker->flags))
		return;
	if (!test_bit(IO_WORKER_F_RUNNING, &worker->flags))
		return;

	clear_bit(IO_WORKER_F_RUNNING, &worker->flags);
	io_wq_dec_running(worker);
}

/*
io_init_new_worker: This function initializes a newly created worker. It associates the worker with its task (task_struct), sets its CPU affinity using the cpu_mask, and adds the worker to the free list and the list of all workers under a spinlock. The worker is marked as free (IO_WORKER_F_FREE), and the task is woken up.
Purpose: Prepares a new worker for use by the workqueue, ensuring proper synchronization and resource tracking.
*/
static void io_init_new_worker(struct io_wq *wq, struct io_wq_acct *acct, struct io_worker *worker,
			       struct task_struct *tsk)
{
	tsk->worker_private = worker;
	worker->task = tsk;
	set_cpus_allowed_ptr(tsk, wq->cpu_mask);

	raw_spin_lock(&acct->workers_lock);
	hlist_nulls_add_head_rcu(&worker->nulls_node, &acct->free_list);
	list_add_tail_rcu(&worker->all_list, &acct->all_list);
	set_bit(IO_WORKER_F_FREE, &worker->flags);
	raw_spin_unlock(&acct->workers_lock);
	wake_up_new_task(tsk);
}

/*
io_wq_work_match_all: A simple utility function that always returns true. It is used as a match function for canceling all pending work.
Purpose: Provides a generic match function for operations that apply to all work items.
*/
static bool io_wq_work_match_all(struct io_wq_work *work, void *data)
{
	return true;
}

/*
io_should_retry_thread: Determines whether a failed thread creation attempt should be retried. It checks for fatal signals, limits the number of retries (WORKER_INIT_LIMIT), and allows retries for specific error codes (e.g., -EAGAIN, -ERESTARTSYS).

Purpose: Prevents infinite retries and ensures retries are only attempted for recoverable errors.
*/
static inline bool io_should_retry_thread(struct io_worker *worker, long err)
{
	/*
	 * Prevent perpetual task_work retry, if the task (or its group) is
	 * exiting.
	 */
	if (fatal_signal_pending(current))
		return false;
	if (worker->init_retries++ >= WORKER_INIT_LIMIT)
		return false;

	switch (err) {
	case -EAGAIN:
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
		return true;
	default:
		return false;
	}
}

/*
queue_create_worker_retry: Schedules a delayed work item to retry worker creation after a short delay. The delay increases with each retry attempt.

Purpose: Provides a mechanism to handle temporary conditions (e.g., signals) that may prevent immediate worker creation.
*/
static void queue_create_worker_retry(struct io_worker *worker)
{
	/*
	 * We only bother retrying because there's a chance that the
	 * failure to create a worker is due to some temporary condition
	 * in the forking task (e.g. outstanding signal); give the task
	 * some time to clear that condition.
	 */
	schedule_delayed_work(&worker->work,
			      msecs_to_jiffies(worker->init_retries * 5));
}

/*
create_worker_cont: A continuation function for worker creation. It attempts to create a thread for the worker and initializes it if successful. If thread creation fails and retries are not allowed, it decrements the running worker count, cancels pending work if no workers remain, and cleans up the worker.

Purpose: Handles the continuation of worker creation, including cleanup and retry logic.
*/
static void create_worker_cont(struct callback_head *cb)
{
	struct io_worker *worker;
	struct task_struct *tsk;
	struct io_wq *wq;
	struct io_wq_acct *acct;

	worker = container_of(cb, struct io_worker, create_work);
	clear_bit_unlock(0, &worker->create_state);
	wq = worker->wq;
	acct = io_wq_get_acct(worker);
	tsk = create_io_thread(io_wq_worker, worker, NUMA_NO_NODE);
	if (!IS_ERR(tsk)) {
		io_init_new_worker(wq, acct, worker, tsk);
		io_worker_release(worker);
		return;
	} else if (!io_should_retry_thread(worker, PTR_ERR(tsk))) {
		atomic_dec(&acct->nr_running);
		raw_spin_lock(&acct->workers_lock);
		acct->nr_workers--;
		if (!acct->nr_workers) {
			struct io_cb_cancel_data match = {
				.fn		= io_wq_work_match_all,
				.cancel_all	= true,
			};

			raw_spin_unlock(&acct->workers_lock);
			while (io_acct_cancel_pending_work(wq, acct, &match))
				;
		} else {
			raw_spin_unlock(&acct->workers_lock);
		}
		io_worker_ref_put(wq);
		kfree(worker);
		return;
	}

	/* re-create attempts grab a new worker ref, drop the existing one */
	io_worker_release(worker);
	queue_create_worker_retry(worker);
}

/*
io_workqueue_create: A delayed work handler that queues a task to create a new worker. If the task fails to queue, the worker is freed.

Purpose: Ensures that worker creation tasks are safely scheduled.
*/
static void io_workqueue_create(struct work_struct *work)
{
	struct io_worker *worker = container_of(work, struct io_worker,
						work.work);
	struct io_wq_acct *acct = io_wq_get_acct(worker);

	if (!io_queue_worker_create(worker, acct, create_worker_cont))
		kfree(worker);
}

/*
create_io_worker and create_worker_cont: If worker creation fails and retries are not allowed, the functions decrement the running worker count, remove the worker from the list of workers, and cancel pending work if no workers remain. This ensures that the workqueue remains in a consistent state.
Purpose: Ensures proper cleanup and resource management in case of worker creation failures.
*/
static bool create_io_worker(struct io_wq *wq, struct io_wq_acct *acct)
{
	struct io_worker *worker;
	struct task_struct *tsk;

	__set_current_state(TASK_RUNNING);

	worker = kzalloc(sizeof(*worker), GFP_KERNEL);
	if (!worker) {
fail:
		atomic_dec(&acct->nr_running);
		raw_spin_lock(&acct->workers_lock);
		acct->nr_workers--;
		raw_spin_unlock(&acct->workers_lock);
		io_worker_ref_put(wq);
		return false;
	}

	refcount_set(&worker->ref, 1);
	worker->wq = wq;
	worker->acct = acct;
	raw_spin_lock_init(&worker->lock);
	init_completion(&worker->ref_done);

	tsk = create_io_thread(io_wq_worker, worker, NUMA_NO_NODE);
	if (!IS_ERR(tsk)) {
		io_init_new_worker(wq, acct, worker, tsk);
	} else if (!io_should_retry_thread(worker, PTR_ERR(tsk))) {
		kfree(worker);
		goto fail;
	} else {
		INIT_DELAYED_WORK(&worker->work, io_workqueue_create);
		queue_create_worker_retry(worker);
	}

	return true;
}

/*
 * Iterate the passed in list and call the specific function for each
 * worker that isn't exiting
 */
 /*
 io_acct_for_each_worker: Iterates over all workers in a specific accounting structure (io_wq_acct) and applies a given function (func) to each worker that is not exiting. If the function returns true, the iteration stops early.

Purpose: Provides a mechanism to perform operations on all active workers in a specific accounting group.
 */
static bool io_acct_for_each_worker(struct io_wq_acct *acct,
				    bool (*func)(struct io_worker *, void *),
				    void *data)
{
	struct io_worker *worker;
	bool ret = false;

	list_for_each_entry_rcu(worker, &acct->all_list, all_list) {
		if (io_worker_get(worker)) {
			/* no task if node is/was offline */
			if (worker->task)
				ret = func(worker, data);
			io_worker_release(worker);
			if (ret)
				break;
		}
	}

	return ret;
}

/*
io_wq_for_each_worker: Iterates over all workers in the workqueue by calling io_acct_for_each_worker for each accounting structure in the workqueue.

Purpose: Extends the iteration logic to cover all workers in the workqueue.
*/
static bool io_wq_for_each_worker(struct io_wq *wq,
				  bool (*func)(struct io_worker *, void *),
				  void *data)
{
	for (int i = 0; i < IO_WQ_ACCT_NR; i++) {
		if (!io_acct_for_each_worker(&wq->acct[i], func, data))
			return false;
	}

	return true;
}

/*
io_wq_worker_wake: This function wakes up a worker by setting a notification signal (__set_notify_signal) and calling wake_up_process on the worker's task.
Purpose: Ensures that idle workers are promptly woken up to handle new tasks.
*/
static bool io_wq_worker_wake(struct io_worker *worker, void *data)
{
	__set_notify_signal(worker->task);
	wake_up_process(worker->task);
	return false;
}

/*
io_run_cancel: Cancels a work item by setting the IO_WQ_WORK_CANCEL flag and executing the work's cancellation logic (do_work and free_work) in a loop.

Purpose: Handles the cancellation of a work item, ensuring proper cleanup.
*/
static void io_run_cancel(struct io_wq_work *work, struct io_wq *wq)
{
	do {
		atomic_or(IO_WQ_WORK_CANCEL, &work->flags);
		wq->do_work(work);
		work = wq->free_work(work);
	} while (work);
}

/*
io_wq_insert_work: Inserts a work item into the accounting structure's work list. If the work is hashed, it ensures that hashed work items are grouped together and processed in order.

Purpose: Organizes work items in the workqueue, supporting both hashed and non-hashed work.
*/
static void io_wq_insert_work(struct io_wq *wq, struct io_wq_acct *acct,
			      struct io_wq_work *work, unsigned int work_flags)
{
	unsigned int hash;
	struct io_wq_work *tail;

	if (!__io_wq_is_hashed(work_flags)) {
append:
		wq_list_add_tail(&work->list, &acct->work_list);
		return;
	}

	hash = __io_get_work_hash(work_flags);
	tail = wq->hash_tail[hash];
	wq->hash_tail[hash] = work;
	if (!tail)
		goto append;

	wq_list_add_after(&work->list, &tail->list, &acct->work_list);
}

/*
io_wq_work_match_item: A utility function that checks if a work item matches a given data pointer. It is used as a match function for canceling specific work items.

Purpose: Simplifies matching logic for targeted work cancellation.
*/
static bool io_wq_work_match_item(struct io_wq_work *work, void *data)
{
	return work == data;
}

/*
io_wq_enqueue: This function enqueues a work item into the workqueue. It first checks if the workqueue is exiting or if the work item is marked for cancellation. If so, it cancels the work using io_run_cancel. Otherwise, it inserts the work into the appropriate accounting structure (acct) using io_wq_insert_work.

Worker Creation: If no free workers are available, the function attempts to create a new worker. If worker creation fails and no workers exist, it cancels the pending work.
Purpose: Adds work items to the workqueue while ensuring proper synchronization and worker availability.
*/
void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work)
{
	unsigned int work_flags = atomic_read(&work->flags);
	struct io_wq_acct *acct = io_work_get_acct(wq, work_flags);
	struct io_cb_cancel_data match = {
		.fn		= io_wq_work_match_item,
		.data		= work,
		.cancel_all	= false,
	};
	bool do_create;

	/*
	 * If io-wq is exiting for this task, or if the request has explicitly
	 * been marked as one that should not get executed, cancel it here.
	 */
	if (test_bit(IO_WQ_BIT_EXIT, &wq->state) ||
	    (work_flags & IO_WQ_WORK_CANCEL)) {
		io_run_cancel(work, wq);
		return;
	}

	raw_spin_lock(&acct->lock);
	io_wq_insert_work(wq, acct, work, work_flags);
	clear_bit(IO_ACCT_STALLED_BIT, &acct->flags);
	raw_spin_unlock(&acct->lock);

	rcu_read_lock();
	do_create = !io_acct_activate_free_worker(acct);
	rcu_read_unlock();

	if (do_create && ((work_flags & IO_WQ_WORK_CONCURRENT) ||
	    !atomic_read(&acct->nr_running))) {
		bool did_create;

		did_create = io_wq_create_worker(wq, acct);
		if (likely(did_create))
			return;

		raw_spin_lock(&acct->workers_lock);
		if (acct->nr_workers) {
			raw_spin_unlock(&acct->workers_lock);
			return;
		}
		raw_spin_unlock(&acct->workers_lock);

		/* fatal condition, failed to create the first worker */
		io_acct_cancel_pending_work(wq, acct, &match);
	}
}

/*
 * Work items that hash to the same value will not be done in parallel.
 * Used to limit concurrent writes, generally hashed by inode.
 */
 /*
 io_wq_hash_work: Marks a work item as hashed by calculating a hash value (e.g., based on an inode) and storing it in the work's flags. Hashed work items are not processed in parallel to avoid conflicts (e.g., concurrent writes to the same file).
Purpose: Limits concurrency for work items that share a common resource, ensuring safe and conflict-free execution.
 */
void io_wq_hash_work(struct io_wq_work *work, void *val)
{
	unsigned int bit;

	bit = hash_ptr(val, IO_WQ_HASH_ORDER);
	atomic_or(IO_WQ_WORK_HASHED | (bit << IO_WQ_HASH_SHIFT), &work->flags);
}

/*
__io_wq_worker_cancel: Cancels a specific work item being executed by a worker. It sets the IO_WQ_WORK_CANCEL flag on the work and notifies the worker's task to handle the cancellation.

Purpose: Provides a low-level mechanism to cancel a specific work item assigned to a worker.
*/
static bool __io_wq_worker_cancel(struct io_worker *worker,
				  struct io_cb_cancel_data *match,
				  struct io_wq_work *work)
{
	if (work && match->fn(work, match->data)) {
		atomic_or(IO_WQ_WORK_CANCEL, &work->flags);
		__set_notify_signal(worker->task);
		return true;
	}

	return false;
}

/*
io_wq_worker_cancel: A higher-level function that locks the worker's state, checks if the current work matches the cancellation criteria, and increments the count of running cancellations (nr_running) if successful.

Purpose: Ensures thread-safe cancellation of work items currently being executed by workers.
*/
static bool io_wq_worker_cancel(struct io_worker *worker, void *data)
{
	struct io_cb_cancel_data *match = data;

	/*
	 * Hold the lock to avoid ->cur_work going out of scope, caller
	 * may dereference the passed in work.
	 */
	raw_spin_lock(&worker->lock);
	if (__io_wq_worker_cancel(worker, match, worker->cur_work))
		match->nr_running++;
	raw_spin_unlock(&worker->lock);

	return match->nr_running && !match->cancel_all;
}

/*
io_wq_remove_pending: Removes a pending work item from the accounting structure's work list. If the work is hashed, it updates the hash tail pointer to maintain consistency.

Purpose: Ensures proper removal of work items from the pending list while maintaining the integrity of hashed work.
*/
static inline void io_wq_remove_pending(struct io_wq *wq,
					struct io_wq_acct *acct,
					 struct io_wq_work *work,
					 struct io_wq_work_node *prev)
{
	unsigned int hash = io_get_work_hash(work);
	struct io_wq_work *prev_work = NULL;

	if (io_wq_is_hashed(work) && work == wq->hash_tail[hash]) {
		if (prev)
			prev_work = container_of(prev, struct io_wq_work, list);
		if (prev_work && io_get_work_hash(prev_work) == hash)
			wq->hash_tail[hash] = prev_work;
		else
			wq->hash_tail[hash] = NULL;
	}
	wq_list_del(&acct->work_list, &work->list, prev);
}

/*
io_acct_cancel_pending_work: Iterates over the pending work list in the accounting structure and cancels matching work items. It uses a match function (io_cb_cancel_data) to identify work items to cancel.

Purpose: Handles the cancellation of pending work items that have not yet started execution.
*/
static bool io_acct_cancel_pending_work(struct io_wq *wq,
					struct io_wq_acct *acct,
					struct io_cb_cancel_data *match)
{
	struct io_wq_work_node *node, *prev;
	struct io_wq_work *work;

	raw_spin_lock(&acct->lock);
	wq_list_for_each(node, prev, &acct->work_list) {
		work = container_of(node, struct io_wq_work, list);
		if (!match->fn(work, match->data))
			continue;
		io_wq_remove_pending(wq, acct, work, prev);
		raw_spin_unlock(&acct->lock);
		io_run_cancel(work, wq);
		match->nr_pending++;
		/* not safe to continue after unlock */
		return true;
	}
	raw_spin_unlock(&acct->lock);

	return false;
}

/*
io_wq_cancel_pending_work: Iterates over all accounting structures in the workqueue and cancels pending work items. If cancel_all is set, it retries until all matching work items are canceled.

Purpose: Provides a unified mechanism to cancel all or specific pending work items across the workqueue.
*/
static void io_wq_cancel_pending_work(struct io_wq *wq,
				      struct io_cb_cancel_data *match)
{
	int i;
retry:
	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		struct io_wq_acct *acct = io_get_acct(wq, i == 0);

		if (io_acct_cancel_pending_work(wq, acct, match)) {
			if (match->cancel_all)
				goto retry;
			break;
		}
	}
}

/*
io_acct_cancel_running_work: Cancels work items currently being executed by workers in a specific accounting structure. It iterates over all workers and signals cancellation for matching work items.

Purpose: Attempts to cancel work items that are actively running.
*/
static void io_acct_cancel_running_work(struct io_wq_acct *acct,
					struct io_cb_cancel_data *match)
{
	raw_spin_lock(&acct->workers_lock);
	io_acct_for_each_worker(acct, io_wq_worker_cancel, match);
	raw_spin_unlock(&acct->workers_lock);
}

/*
io_wq_cancel_running_work: Extends io_acct_cancel_running_work to handle all accounting structures in the workqueue.

Purpose: Provides a unified mechanism to cancel running work items across the workqueue.
*/
static void io_wq_cancel_running_work(struct io_wq *wq,
				       struct io_cb_cancel_data *match)
{
	rcu_read_lock();

	for (int i = 0; i < IO_WQ_ACCT_NR; i++)
		io_acct_cancel_running_work(&wq->acct[i], match);

	rcu_read_unlock();
}

/*
io_wq_cancel_cb: A high-level function that handles both pending and running work cancellations. It first tries to cancel pending work and, if unsuccessful, attempts to cancel running work. It returns a status indicating whether the cancellation was successful or if the work was not found.

Purpose: Provides a comprehensive interface for canceling work items in the workqueue.
*/
enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
				  void *data, bool cancel_all)
{
	struct io_cb_cancel_data match = {
		.fn		= cancel,
		.data		= data,
		.cancel_all	= cancel_all,
	};

	/*
	 * First check pending list, if we're lucky we can just remove it
	 * from there. CANCEL_OK means that the work is returned as-new,
	 * no completion will be posted for it.
	 *
	 * Then check if a free (going busy) or busy worker has the work
	 * currently running. If we find it there, we'll return CANCEL_RUNNING
	 * as an indication that we attempt to signal cancellation. The
	 * completion will run normally in this case.
	 *
	 * Do both of these while holding the acct->workers_lock, to ensure that
	 * we'll find a work item regardless of state.
	 */
	io_wq_cancel_pending_work(wq, &match);
	if (match.nr_pending && !match.cancel_all)
		return IO_WQ_CANCEL_OK;

	io_wq_cancel_running_work(wq, &match);
	if (match.nr_running && !match.cancel_all)
		return IO_WQ_CANCEL_RUNNING;

	if (match.nr_running)
		return IO_WQ_CANCEL_RUNNING;
	if (match.nr_pending)
		return IO_WQ_CANCEL_OK;
	return IO_WQ_CANCEL_NOTFOUND;
}

/*
io_wq_hash_wake: Handles wake-up events for hashed work items. It clears the stalled flag for accounting structures and activates free workers to process the work.

Purpose: Ensures that stalled hashed work items are promptly processed by available workers.

*/
static int io_wq_hash_wake(struct wait_queue_entry *wait, unsigned mode,
			    int sync, void *key)
{
	struct io_wq *wq = container_of(wait, struct io_wq, wait);
	int i;

	list_del_init(&wait->entry);

	rcu_read_lock();
	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		struct io_wq_acct *acct = &wq->acct[i];

		if (test_and_clear_bit(IO_ACCT_STALLED_BIT, &acct->flags))
			io_acct_activate_free_worker(acct);
	}
	rcu_read_unlock();
	return 1;
}

/*
io_wq_create: Creates and initializes a new io_wq instance. It allocates memory for the workqueue, sets up CPU affinity, initializes accounting structures, and registers the workqueue with the CPU hotplug subsystem.

Purpose: Dynamically creates a workqueue with bounded and unbounded worker configurations, ensuring proper resource allocation and initialization.
*/
struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data)
{
	int ret, i;
	struct io_wq *wq;

	if (WARN_ON_ONCE(!data->free_work || !data->do_work))
		return ERR_PTR(-EINVAL);
	if (WARN_ON_ONCE(!bounded))
		return ERR_PTR(-EINVAL);

	wq = kzalloc(sizeof(struct io_wq), GFP_KERNEL);
	if (!wq)
		return ERR_PTR(-ENOMEM);

	refcount_inc(&data->hash->refs);
	wq->hash = data->hash;
	wq->free_work = data->free_work;
	wq->do_work = data->do_work;

	ret = -ENOMEM;

	if (!alloc_cpumask_var(&wq->cpu_mask, GFP_KERNEL))
		goto err;
	cpuset_cpus_allowed(data->task, wq->cpu_mask);
	wq->acct[IO_WQ_ACCT_BOUND].max_workers = bounded;
	wq->acct[IO_WQ_ACCT_UNBOUND].max_workers =
				task_rlimit(current, RLIMIT_NPROC);
	INIT_LIST_HEAD(&wq->wait.entry);
	wq->wait.func = io_wq_hash_wake;
	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		struct io_wq_acct *acct = &wq->acct[i];

		atomic_set(&acct->nr_running, 0);

		raw_spin_lock_init(&acct->workers_lock);
		INIT_HLIST_NULLS_HEAD(&acct->free_list, 0);
		INIT_LIST_HEAD(&acct->all_list);

		INIT_WQ_LIST(&acct->work_list);
		raw_spin_lock_init(&acct->lock);
	}

	wq->task = get_task_struct(data->task);
	atomic_set(&wq->worker_refs, 1);
	init_completion(&wq->worker_done);
	ret = cpuhp_state_add_instance_nocalls(io_wq_online, &wq->cpuhp_node);
	if (ret)
		goto err;

	return wq;
err:
	io_wq_put_hash(data->hash);
	free_cpumask_var(wq->cpu_mask);
	kfree(wq);
	return ERR_PTR(ret);
}

/*
io_task_work_match: Matches a task's callback with a specific workqueue. It is used to identify and cancel task work associated with the workqueue.

Purpose: Simplifies the identification of task work for cancellation.
*/
static bool io_task_work_match(struct callback_head *cb, void *data)
{
	struct io_worker *worker;

	if (cb->func != create_worker_cb && cb->func != create_worker_cont)
		return false;
	worker = container_of(cb, struct io_worker, create_work);
	return worker->wq == data;
}

/*
io_wq_exit_start: Marks the workqueue as exiting by setting the IO_WQ_BIT_EXIT flag.

Purpose: Signals the start of the workqueue shutdown process.
*/
void io_wq_exit_start(struct io_wq *wq)
{
	set_bit(IO_WQ_BIT_EXIT, &wq->state);
}

/*
io_wq_cancel_tw_create: Cancels task work associated with worker creation. It ensures that no new workers are created during the shutdown process.

Purpose: Prevents resource leaks and ensures a clean shutdown of the workqueue.
*/
static void io_wq_cancel_tw_create(struct io_wq *wq)
{
	struct callback_head *cb;

	while ((cb = task_work_cancel_match(wq->task, io_task_work_match, wq)) != NULL) {
		struct io_worker *worker;

		worker = container_of(cb, struct io_worker, create_work);
		io_worker_cancel_cb(worker);
		/*
		 * Only the worker continuation helper has worker allocated and
		 * hence needs freeing.
		 */
		if (cb->func == create_worker_cont)
			kfree(worker);
	}
}

/*
io_wq_exit_workers: Cancels all task work, wakes up all workers, and waits for their completion. It also removes the workqueue from the hash wait list.

Purpose: Ensures a clean and orderly shutdown of all workers in the workqueue.
*/
static void io_wq_exit_workers(struct io_wq *wq)
{
	if (!wq->task)
		return;

	io_wq_cancel_tw_create(wq);

	rcu_read_lock();
	io_wq_for_each_worker(wq, io_wq_worker_wake, NULL);
	rcu_read_unlock();
	io_worker_ref_put(wq);
	wait_for_completion(&wq->worker_done);

	spin_lock_irq(&wq->hash->wait.lock);
	list_del_init(&wq->wait.entry);
	spin_unlock_irq(&wq->hash->wait.lock);

	put_task_struct(wq->task);
	wq->task = NULL;
}

/*
io_wq_destroy: Frees all resources associated with the workqueue, including pending work items, CPU masks, and the workqueue itself.

Purpose: Completes the destruction of the workqueue after all workers have exited.
*/
static void io_wq_destroy(struct io_wq *wq)
{
	struct io_cb_cancel_data match = {
		.fn		= io_wq_work_match_all,
		.cancel_all	= true,
	};

	cpuhp_state_remove_instance_nocalls(io_wq_online, &wq->cpuhp_node);
	io_wq_cancel_pending_work(wq, &match);
	free_cpumask_var(wq->cpu_mask);
	io_wq_put_hash(wq->hash);
	kfree(wq);
}

/*
io_wq_put_and_exit: Combines io_wq_exit_workers and io_wq_destroy to fully shut down and clean up the workqueue.

Purpose: Provides a single entry point for shutting down and destroying the workqueue.
*/
void io_wq_put_and_exit(struct io_wq *wq)
{
	WARN_ON_ONCE(!test_bit(IO_WQ_BIT_EXIT, &wq->state));

	io_wq_exit_workers(wq);
	io_wq_destroy(wq);
}

struct online_data {
	unsigned int cpu;
	bool online;
};

/*
io_wq_worker_affinity: Adjusts the CPU affinity of a worker based on whether a CPU is online or offline.

Purpose: Ensures that workers are only scheduled on available CPUs.
*/
static bool io_wq_worker_affinity(struct io_worker *worker, void *data)
{
	struct online_data *od = data;

	if (od->online)
		cpumask_set_cpu(od->cpu, worker->wq->cpu_mask);
	else
		cpumask_clear_cpu(od->cpu, worker->wq->cpu_mask);
	return false;
}

/*
__io_wq_cpu_online: Updates the CPU affinity of all workers in the workqueue when a CPU comes online or goes offline.

Purpose: Dynamically adjusts worker CPU affinity in response to CPU hotplug events.
*/
static int __io_wq_cpu_online(struct io_wq *wq, unsigned int cpu, bool online)
{
	struct online_data od = {
		.cpu = cpu,
		.online = online
	};

	rcu_read_lock();
	io_wq_for_each_worker(wq, io_wq_worker_affinity, &od);
	rcu_read_unlock();
	return 0;
}

/*
io_wq_cpu_online and io_wq_cpu_offline: Wrapper functions for handling CPU online and offline events, respectively.

Purpose: Integrates the workqueue with the CPU hotplug subsystem.
*/
static int io_wq_cpu_online(unsigned int cpu, struct hlist_node *node)
{
	struct io_wq *wq = hlist_entry_safe(node, struct io_wq, cpuhp_node);

	return __io_wq_cpu_online(wq, cpu, true);
}

static int io_wq_cpu_offline(unsigned int cpu, struct hlist_node *node)
{
	struct io_wq *wq = hlist_entry_safe(node, struct io_wq, cpuhp_node);

	return __io_wq_cpu_online(wq, cpu, false);
}

/*
io_wq_cpu_affinity: Sets or retrieves the CPU affinity mask for the workqueue. It ensures that the requested mask is a subset of the allowed CPUs.

Purpose: Provides a user-facing interface for managing workqueue CPU affinity.
*/
int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask)
{
	cpumask_var_t allowed_mask;
	int ret = 0;

	if (!tctx || !tctx->io_wq)
		return -EINVAL;

	if (!alloc_cpumask_var(&allowed_mask, GFP_KERNEL))
		return -ENOMEM;

	rcu_read_lock();
	cpuset_cpus_allowed(tctx->io_wq->task, allowed_mask);
	if (mask) {
		if (cpumask_subset(mask, allowed_mask))
			cpumask_copy(tctx->io_wq->cpu_mask, mask);
		else
			ret = -EINVAL;
	} else {
		cpumask_copy(tctx->io_wq->cpu_mask, allowed_mask);
	}
	rcu_read_unlock();

	free_cpumask_var(allowed_mask);
	return ret;
}

/*
 * Set max number of unbounded workers, returns old value. If new_count is 0,
 * then just return the old value.
 */

 /*
 io_wq_max_workers: Sets or retrieves the maximum number of bounded and unbounded workers for the workqueue. It ensures that the limits do not exceed the process's resource limits (RLIMIT_NPROC).
Purpose: Dynamically adjusts the worker limits to balance resource usage and workload demands.
 */
int io_wq_max_workers(struct io_wq *wq, int *new_count)
{
	struct io_wq_acct *acct;
	int prev[IO_WQ_ACCT_NR];
	int i;

	BUILD_BUG_ON((int) IO_WQ_ACCT_BOUND   != (int) IO_WQ_BOUND);
	BUILD_BUG_ON((int) IO_WQ_ACCT_UNBOUND != (int) IO_WQ_UNBOUND);
	BUILD_BUG_ON((int) IO_WQ_ACCT_NR      != 2);

	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		if (new_count[i] > task_rlimit(current, RLIMIT_NPROC))
			new_count[i] = task_rlimit(current, RLIMIT_NPROC);
	}

	for (i = 0; i < IO_WQ_ACCT_NR; i++)
		prev[i] = 0;

	rcu_read_lock();

	for (i = 0; i < IO_WQ_ACCT_NR; i++) {
		acct = &wq->acct[i];
		raw_spin_lock(&acct->workers_lock);
		prev[i] = max_t(int, acct->max_workers, prev[i]);
		if (new_count[i])
			acct->max_workers = new_count[i];
		raw_spin_unlock(&acct->workers_lock);
	}
	rcu_read_unlock();

	for (i = 0; i < IO_WQ_ACCT_NR; i++)
		new_count[i] = prev[i];

	return 0;
}

/*
io_wq_init: Registers the workqueue with the CPU hotplug subsystem during system initialization.
Purpose: Ensures that the workqueue is properly integrated with the system's CPU management infrastructure.
*/
static __init int io_wq_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, "io-wq/online",
					io_wq_cpu_online, io_wq_cpu_offline);
	if (ret < 0)
		return ret;
	io_wq_online = ret;
	return 0;
}
subsys_initcall(io_wq_init);
