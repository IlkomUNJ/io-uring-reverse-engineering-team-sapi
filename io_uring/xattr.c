// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/xattr.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "xattr.h"

struct io_xattr {
	struct file			*file;
	struct kernel_xattr_ctx		ctx;
	struct filename			*filename;
};

/*
 This function, io_xattr_cleanup, is responsible for cleaning up resources associated with an I/O request (req) related to extended attributes (xattr). 
 It releases the memory allocated for the filename and attribute name/value.
*/
void io_xattr_cleanup(struct io_kiocb *req)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);

	if (ix->filename)
		putname(ix->filename);

	kfree(ix->ctx.kname);
	kvfree(ix->ctx.kvalue);
}

/*
 This function, io_xattr_finish, is called to finish the I/O request related to extended attributes. 
 It clears the REQ_F_NEED_CLEANUP flag, cleans up resources, and sets the result of the request.
*/
static void io_xattr_finish(struct io_kiocb *req, int ret)
{
	req->flags &= ~REQ_F_NEED_CLEANUP;

	io_xattr_cleanup(req);
	io_req_set_res(req, ret, 0);
}

/*
 This function, io_fgetxattr, is responsible for getting the extended attribute of a file descriptor (req->file). 
 It calls the file_getxattr function and finishes the request using io_xattr_finish.
*/
static int __io_getxattr_prep(struct io_kiocb *req,
			      const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *name;
	int ret;

	ix->filename = NULL;
	ix->ctx.kvalue = NULL;
	name = u64_to_user_ptr(READ_ONCE(sqe->addr));
	ix->ctx.value = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ix->ctx.size = READ_ONCE(sqe->len);
	ix->ctx.flags = READ_ONCE(sqe->xattr_flags);

	if (ix->ctx.flags)
		return -EINVAL;

	ix->ctx.kname = kmalloc(sizeof(*ix->ctx.kname), GFP_KERNEL);
	if (!ix->ctx.kname)
		return -ENOMEM;

	ret = import_xattr_name(ix->ctx.kname, name);
	if (ret) {
		kfree(ix->ctx.kname);
		return ret;
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 This function, io_fgetxattr_prep, prepares the I/O request for getting the extended attribute of a file descriptor. 
 It calls __io_getxattr_prep to set up the request and checks for errors.
*/
int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_getxattr_prep(req, sqe);
}

/*
 This function, io_getxattr_prep, prepares the I/O request for getting the extended attribute of a file. 
 It calls __io_getxattr_prep to set up the request and checks for errors.
*/
int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *path;
	int ret;

	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ret = __io_getxattr_prep(req, sqe);
	if (ret)
		return ret;

	path = u64_to_user_ptr(READ_ONCE(sqe->addr3));

	ix->filename = getname(path);
	if (IS_ERR(ix->filename))
		return PTR_ERR(ix->filename);

	return 0;
}

/*
 This function, io_fgetxattr, is responsible for getting the extended attribute of a file descriptor (req->file). 
 It calls the file_getxattr function and finishes the request using io_xattr_finish.
*/
int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = file_getxattr(req->file, &ix->ctx);
	io_xattr_finish(req, ret);
	return IOU_OK;
}

/*
 This function, io_getxattr, is responsible for getting the extended attribute of a file. 
 It calls the filename_getxattr function and finishes the request using io_xattr_finish.
*/
int io_getxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = filename_getxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);
	ix->filename = NULL;
	io_xattr_finish(req, ret);
	return IOU_OK;
}

/*
 This function, __io_setxattr_prep, prepares the I/O request for setting the extended attribute of a file. 
 It sets up the request structure and checks for errors.
*/
static int __io_setxattr_prep(struct io_kiocb *req,
			const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *name;
	int ret;

	ix->filename = NULL;
	name = u64_to_user_ptr(READ_ONCE(sqe->addr));
	ix->ctx.cvalue = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	ix->ctx.kvalue = NULL;
	ix->ctx.size = READ_ONCE(sqe->len);
	ix->ctx.flags = READ_ONCE(sqe->xattr_flags);

	ix->ctx.kname = kmalloc(sizeof(*ix->ctx.kname), GFP_KERNEL);
	if (!ix->ctx.kname)
		return -ENOMEM;

	ret = setxattr_copy(name, &ix->ctx);
	if (ret) {
		kfree(ix->ctx.kname);
		return ret;
	}

	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 This function, io_setxattr_prep, prepares the I/O request for setting the extended attribute of a file. 
 It calls __io_setxattr_prep to set up the request and checks for errors.
*/
int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	const char __user *path;
	int ret;

	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	ret = __io_setxattr_prep(req, sqe);
	if (ret)
		return ret;

	path = u64_to_user_ptr(READ_ONCE(sqe->addr3));

	ix->filename = getname(path);
	if (IS_ERR(ix->filename))
		return PTR_ERR(ix->filename);

	return 0;
}

/*
 This function, io_fsetxattr, is responsible for setting the extended attribute of a file descriptor (req->file). 
 It calls the file_setxattr function and finishes the request using io_xattr_finish.
*/
int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_setxattr_prep(req, sqe);
}

/*
 This function, io_fsetxattr, is responsible for setting the extended attribute of a file descriptor (req->file). 
 It calls the file_setxattr function and finishes the request using io_xattr_finish.
*/
int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = file_setxattr(req->file, &ix->ctx);
	io_xattr_finish(req, ret);
	return IOU_OK;
}

/*
 This function, io_setxattr, is responsible for setting the extended attribute of a file. 
 It calls the filename_setxattr function and finishes the request using io_xattr_finish.
*/
int io_setxattr(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_xattr *ix = io_kiocb_to_cmd(req, struct io_xattr);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = filename_setxattr(AT_FDCWD, ix->filename, LOOKUP_FOLLOW, &ix->ctx);
	ix->filename = NULL;
	io_xattr_finish(req, ret);
	return IOU_OK;
}
