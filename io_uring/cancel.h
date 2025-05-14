// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	union {
		u64 data;
		struct file *file;
	};
	u8 opcode;
	u32 flags;
	int seq;
};

int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);

int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);

int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
			  bool (*cancel)(struct io_kiocb *));

int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
		     bool (*cancel)(struct io_kiocb *));

/*
The io_cancel_match_sequence function is a static inline utility function used in the io_uring subsystem to determine whether a specific I/O request (req) matches a given cancellation sequence (sequence). 
It also updates the request's cancellation sequence if it has not been set yet. The function operates on an io_kiocb structure (req), which represents an individual I/O request, and takes an integer (sequence) as input. 
It returns a boolean value indicating whether the request matches the provided sequence.
*/			 
static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence)
{
	if (req->cancel_seq_set && sequence == req->work.cancel_seq)
		return true;

	req->cancel_seq_set = true;
	req->work.cancel_seq = sequence;
	return false;
}

#endif
