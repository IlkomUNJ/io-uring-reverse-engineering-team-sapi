#ifndef IOU_REQ_REF_H
#define IOU_REQ_REF_H

#include <linux/atomic.h>
#include <linux/io_uring_types.h>

/*
 * Shamelessly stolen from the mm implementation of page reference checking,
 * see commit f958d7b528b1 for details.
 */
#define req_ref_zero_or_close_to_overflow(req)	\
	((unsigned int) atomic_read(&(req->refs)) + 127u <= 127u)

/*
This function increments the reference count of an io_kiocb object (req) and returns true if the new count is non-zero. 
It also checks if the object has reference counting enabled (REQ_F_REFCOUNT flag) and warns if not.
*/
static inline bool req_ref_inc_not_zero(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	return atomic_inc_not_zero(&req->refs);
}

/*
This function decrements the reference count of an io_kiocb object (req) and returns true if the new count is zero.
*/
static inline bool req_ref_put_and_test_atomic(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(data_race(req->flags) & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	return atomic_dec_and_test(&req->refs);
}

/*This function decrements the reference count of an io_kiocb object (req) and returns true if the new count is zero. 
However, if reference counting is not enabled for the object (REQ_F_REFCOUNT flag is not set), it immediately returns true without modifying the count. It also warns if the count is close to overflowing.
*/
static inline bool req_ref_put_and_test(struct io_kiocb *req)
{
	if (likely(!(req->flags & REQ_F_REFCOUNT)))
		return true;

	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	return atomic_dec_and_test(&req->refs);
}

/*
This function decrements the reference count of an io_kiocb object (req) and returns true if the new count is zero.
It also checks if the object has reference counting enabled (REQ_F_REFCOUNT flag) and warns if not.
*/
static inline void req_ref_get(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	atomic_inc(&req->refs);
}

/*
 This function decrements the reference count of an io_kiocb object (req) by 1, while checking for two conditions:
	1. The object has reference counting enabled (REQ_F_REFCOUNT flag is set).
	2. he reference count is not close to overflowing.
If either condition is not met, it raises a warning.
*/
static inline void req_ref_put(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	atomic_dec(&req->refs);
}

/*
This function sets the reference count of an io_kiocb object (req) to a specified value (nr).
*/
static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)
{
	if (!(req->flags & REQ_F_REFCOUNT)) {
		req->flags |= REQ_F_REFCOUNT;
		atomic_set(&req->refs, nr);
	}
}

/*
This function sets the reference count of an io_kiocb object (req) to 1.
*/
static inline void io_req_set_refcount(struct io_kiocb *req)
{
	__io_req_set_refcount(req, 1);
}
#endif
