// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/fsnotify.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "sync.h"

struct io_sync {
	struct file			*file;
	loff_t				len;
	loff_t				off;
	int				flags;
	int				mode;
};

/* 
 This is a bit of a hack, but we need to be able to pass the file
 descriptor to the sync_file_range() syscall.  The file descriptor
 is passed in the sqe->fd field, and we need to save it in the
 io_sync structure.
 */
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

	if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
		return -EINVAL;

	sync->off = READ_ONCE(sqe->off);
	sync->len = READ_ONCE(sqe->len);
	sync->flags = READ_ONCE(sqe->sync_range_flags);
	req->flags |= REQ_F_FORCE_ASYNC;

	return 0;
}

/*
 This function, io_sync_file_range, synchronizes a file range using the sync_file_range system call. It checks if the operation is being issued in a non-blocking context, and if so, triggers a warning. 
 The function then calls sync_file_range with the file descriptor, offset, length, and flags from the io_sync structure, and sets the result of the operation in the io_kiocb request structure. The function returns IOU_OK to indicate successful completion.
*/
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	int ret;

	/* sync_file_range always requires a blocking context */
	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = sync_file_range(req->file, sync->off, sync->len, sync->flags);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 This function, io_fsync_prep, prepares the io_kiocb request for a file synchronization operation. 
 It checks if the request contains any invalid fields and sets the flags, offset, and length for the synchronization operation. 
 The function returns 0 on success or an error code on failure.
*/
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

	if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
		return -EINVAL;

	sync->flags = READ_ONCE(sqe->fsync_flags);
	if (unlikely(sync->flags & ~IORING_FSYNC_DATASYNC))
		return -EINVAL;

	sync->off = READ_ONCE(sqe->off);
	sync->len = READ_ONCE(sqe->len);
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 This function, io_fsync, performs a file synchronization operation using the fsync system call. 
 It checks if the operation is being issued in a non-blocking context and triggers a warning if so. 
 The function then calls vfs_fsync_range with the file descriptor, offset, length, and flags from the io_sync structure, and sets the result of the operation in the io_kiocb request structure. 
 The function returns IOU_OK to indicate successful completion.
*/
int io_fsync(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	loff_t end = sync->off + sync->len;
	int ret;

	/* fsync always requires a blocking context */
	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = vfs_fsync_range(req->file, sync->off, end > 0 ? end : LLONG_MAX,
				sync->flags & IORING_FSYNC_DATASYNC);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 This function, io_fallocate_prep, prepares the io_kiocb request for a file allocation operation. 
 It checks if the request contains any invalid fields and sets the offset, length, and mode for the allocation operation. 
 The function returns 0 on success or an error code on failure.
*/
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

	if (sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	sync->off = READ_ONCE(sqe->off);
	sync->len = READ_ONCE(sqe->addr);
	sync->mode = READ_ONCE(sqe->len);
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 This function, io_fallocate, handles file allocation requests in the io_uring library. 
 It checks if the request is non-blocking, warns if so (since fallocate requires a blocking context), and then calls the vfs_fallocate function to perform the actual file allocation. If successful, it notifies the file system of the modification and sets the result of the operation in the request structure.
*/
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	int ret;

	/* fallocate always requiring blocking context */
	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = vfs_fallocate(req->file, sync->mode, sync->off, sync->len);
	if (ret >= 0)
		fsnotify_modify(req->file);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
