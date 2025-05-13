// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/splice.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "splice.h"

struct io_splice {
	struct file			*file_out;
	loff_t				off_out;
	loff_t				off_in;
	u64				len;
	int				splice_fd_in;
	unsigned int			flags;
	struct io_rsrc_node		*rsrc_node;
};

/*
 io_splice_prep - prepare a splice command
*/
static int __io_splice_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	unsigned int valid_flags = SPLICE_F_FD_IN_FIXED | SPLICE_F_ALL;

	sp->len = READ_ONCE(sqe->len);
	sp->flags = READ_ONCE(sqe->splice_flags);
	if (unlikely(sp->flags & ~valid_flags))
		return -EINVAL;
	sp->splice_fd_in = READ_ONCE(sqe->splice_fd_in);
	sp->rsrc_node = NULL;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 This function, io_tee_prep, prepares an I/O request for a tee operation. It checks if splice_off_in or off fields in the submission queue entry (sqe) are non-zero, and if so, returns an invalid argument error (-EINVAL). 
 Otherwise, it calls __io_splice_prep to continue preparing the splice operation.
*/
int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (READ_ONCE(sqe->splice_off_in) || READ_ONCE(sqe->off))
		return -EINVAL;
	return __io_splice_prep(req, sqe);
}

/*
 This function, io_splice_cleanup, is responsible for cleaning up resources associated with a splice operation. 
 It checks if the resource node (rsrc_node) is not NULL, and if so, it decrements the reference count on the resource node using io_put_rsrc_node.
*/
void io_splice_cleanup(struct io_kiocb *req)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);

	if (sp->rsrc_node)
		io_put_rsrc_node(req->ctx, sp->rsrc_node);
}

/*	
 This function, io_splice_get_file, retrieves a file descriptor for the splice operation. 
 It checks if the SPLICE_F_FD_IN_FIXED flag is set in the flags field of the io_splice structure. 
 If it is not set, it calls io_file_get_normal to get a normal file descriptor using the splice_fd_in field. 
 If the flag is set, it locks the submission context (ctx) and looks up the resource node in the file table using io_rsrc_node_lookup. 
 If a valid node is found, it increments the reference count on the node and retrieves the file descriptor using io_slot_file.
*/
static struct file *io_splice_get_file(struct io_kiocb *req,
				       unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_rsrc_node *node;
	struct file *file = NULL;

	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		return io_file_get_normal(req, sp->splice_fd_in);

	io_ring_submit_lock(ctx, issue_flags);
	node = io_rsrc_node_lookup(&ctx->file_table.data, sp->splice_fd_in);
	if (node) {
		node->refs++;
		sp->rsrc_node = node;
		file = io_slot_file(node);
		req->flags |= REQ_F_NEED_CLEANUP;
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return file;
}

/*
 This is a C function named io_tee that performs a tee operation in the context of the io_uring library. 
*/
int io_tee(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	struct file *in;
	ssize_t ret = 0;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	in = io_splice_get_file(req, issue_flags);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	if (sp->len)
		ret = do_tee(in, out, sp->len, flags);

	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);
done:
	if (ret != sp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 This function, io_splice_prep, prepares a splice operation by initializing the off_in and off_out fields of the io_splice structure. 
 It calls __io_splice_prep to continue preparing the splice operation.
*/
int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);

	sp->off_in = READ_ONCE(sqe->splice_off_in);
	sp->off_out = READ_ONCE(sqe->off);
	return __io_splice_prep(req, sqe);
}

/*
 This is a C function named io_splice that performs a splice operation in the context of the io_uring library. 
*/
int io_splice(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	loff_t *poff_in, *poff_out;
	struct file *in;
	ssize_t ret = 0;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	in = io_splice_get_file(req, issue_flags);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	poff_in = (sp->off_in == -1) ? NULL : &sp->off_in;
	poff_out = (sp->off_out == -1) ? NULL : &sp->off_out;

	if (sp->len)
		ret = do_splice(in, poff_in, out, poff_out, sp->len, flags);

	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);
done:
	if (ret != sp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
