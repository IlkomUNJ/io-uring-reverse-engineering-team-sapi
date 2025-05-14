// SPDX-License-Identifier: GPL-2.0

int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags, // close a fixed file descriptor
		     unsigned int offset);

int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe); // prepare the io_openat operation
int io_openat(struct io_kiocb *req, unsigned int issue_flags); // execute the io_openat operation
void io_open_cleanup(struct io_kiocb *req); // cleanup the io_open operation

int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe); // prepare the io_openat2 operation
int io_openat2(struct io_kiocb *req, unsigned int issue_flags); // execute the io_openat2 operation

int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe); // prepare the io_close operation
int io_close(struct io_kiocb *req, unsigned int issue_flags); // execute the io_close operation

int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe); // prepare the io_install_fixed_fd operation
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags); // execute the io_install_fixed_fd operation
