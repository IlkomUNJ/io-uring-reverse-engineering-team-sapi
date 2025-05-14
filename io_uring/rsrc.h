// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_RSRC_H
#define IOU_RSRC_H

#include <linux/io_uring_types.h>
#include <linux/lockdep.h>

#define IO_VEC_CACHE_SOFT_CAP		256

enum {
	IORING_RSRC_FILE		= 0,
	IORING_RSRC_BUFFER		= 1,
};

struct io_rsrc_node {
	unsigned char			type;
	int				refs;

	u64 tag;
	union {
		unsigned long file_ptr;
		struct io_mapped_ubuf *buf;
	};
};

enum {
	IO_IMU_DEST	= 1 << ITER_DEST,
	IO_IMU_SOURCE	= 1 << ITER_SOURCE,
};

struct io_mapped_ubuf {
	u64		ubuf;
	unsigned int	len;
	unsigned int	nr_bvecs;
	unsigned int    folio_shift;
	refcount_t	refs;
	unsigned long	acct_pages;
	void		(*release)(void *);
	void		*priv;
	bool		is_kbuf;
	u8		dir;
	struct bio_vec	bvec[] __counted_by(nr_bvecs);
};

struct io_imu_folio_data {
	/* Head folio can be partially included in the fixed buf */
	unsigned int	nr_pages_head;
	/* For non-head/tail folios, has to be fully included */
	unsigned int	nr_pages_mid;
	unsigned int	folio_shift;
	unsigned int	nr_folios;
};

bool io_rsrc_cache_init(struct io_ring_ctx *ctx);
void io_rsrc_cache_free(struct io_ring_ctx *ctx);
struct io_rsrc_node *io_rsrc_node_alloc(struct io_ring_ctx *ctx, int type);
void io_free_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node);
void io_rsrc_data_free(struct io_ring_ctx *ctx, struct io_rsrc_data *data);
int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr);

struct io_rsrc_node *io_find_buf_node(struct io_kiocb *req,
				      unsigned issue_flags);
int io_import_reg_buf(struct io_kiocb *req, struct iov_iter *iter,
			u64 buf_addr, size_t len, int ddir,
			unsigned issue_flags);
int io_import_reg_vec(int ddir, struct iov_iter *iter,
			struct io_kiocb *req, struct iou_vec *vec,
			unsigned nr_iovs, unsigned issue_flags);
int io_prep_reg_iovec(struct io_kiocb *req, struct iou_vec *iv,
			const struct iovec __user *uvec, size_t uvec_segs);

int io_register_clone_buffers(struct io_ring_ctx *ctx, void __user *arg);
int io_sqe_buffers_unregister(struct io_ring_ctx *ctx);
int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned int nr_args, u64 __user *tags);
int io_sqe_files_unregister(struct io_ring_ctx *ctx);
int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
			  unsigned nr_args, u64 __user *tags);

int io_register_files_update(struct io_ring_ctx *ctx, void __user *arg,
			     unsigned nr_args);
int io_register_rsrc_update(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned size, unsigned type);
int io_register_rsrc(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int size, unsigned int type);
int io_buffer_validate(struct iovec *iov);

bool io_check_coalesce_buffer(struct page **page_array, int nr_pages,
			      struct io_imu_folio_data *data);

/*
 This function io_rsrc_node_lookup looks up a resource node in an array of nodes based on a given index. 
 It returns the node at the specified index if it exists, otherwise it returns NULL. The array_index_nospec function is used to prevent speculative execution attacks.
*/
static inline struct io_rsrc_node *io_rsrc_node_lookup(struct io_rsrc_data *data,
						       int index)
{
	if (index < data->nr)
		return data->nodes[array_index_nospec(index, data->nr)];
	return NULL;
}

/*
 This function io_get_rsrc_node increments the reference count of a resource node and returns it. 
 It is used to ensure that the node is not freed while it is still in use.
*/
static inline void io_put_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (!--node->refs)
		io_free_rsrc_node(ctx, node);
}

/*
 This function io_reset_rsrc_node resets a resource node in an array of nodes at a specified index. 
 It decrements the reference count of the node and sets the node at the index to NULL. 
 It returns true if the node was reset, otherwise it returns false.
*/
static inline bool io_reset_rsrc_node(struct io_ring_ctx *ctx,
				      struct io_rsrc_data *data, int index)
{
	struct io_rsrc_node *node = data->nodes[index];

	if (!node)
		return false;
	io_put_rsrc_node(ctx, node);
	data->nodes[index] = NULL;
	return true;
}

/*
 This function io_req_put_rsrc_nodes decrements the reference count of the resource nodes associated with a request. 
 It is used to clean up the nodes when they are no longer
*/
static inline void io_req_put_rsrc_nodes(struct io_kiocb *req)
{
	if (req->file_node) {
		io_put_rsrc_node(req->ctx, req->file_node);
		req->file_node = NULL;
	}
	if (req->flags & REQ_F_BUF_NODE) {
		io_put_rsrc_node(req->ctx, req->buf_node);
		req->buf_node = NULL;
	}
}

/*
 This function io_req_assign_rsrc_node assigns a resource node to a request. 
 It increments the reference count of the node and sets it in the request.
*/
static inline void io_req_assign_rsrc_node(struct io_rsrc_node **dst_node,
					   struct io_rsrc_node *node)
{
	node->refs++;
	*dst_node = node;
}

/*
 This function io_req_assign_buf_node assigns a buffer node to a request. 
 It sets the buffer node in the request and marks the request as having a buffer node.
*/
static inline void io_req_assign_buf_node(struct io_kiocb *req,
					  struct io_rsrc_node *node)
{
	io_req_assign_rsrc_node(&req->buf_node, node);
	req->flags |= REQ_F_BUF_NODE;
}

int io_files_update(struct io_kiocb *req, unsigned int issue_flags);
int io_files_update_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

int __io_account_mem(struct user_struct *user, unsigned long nr_pages);

/*
 This function __io_unaccount_mem decrements the memory usage of a user by the specified number of pages. 
 It is used to release memory that was previously accounted for.
*/
static inline void __io_unaccount_mem(struct user_struct *user,
				      unsigned long nr_pages)
{
	atomic_long_sub(nr_pages, &user->locked_vm);
}

void io_vec_free(struct iou_vec *iv);
int io_vec_realloc(struct iou_vec *iv, unsigned nr_entries);

/*
 This function io_vec_reset_iovec resets the I/O vector in the iou_vec structure. 
 It frees the existing I/O vector and assigns a new one to it.
*/
static inline void io_vec_reset_iovec(struct iou_vec *iv,
				      struct iovec *iovec, unsigned nr)
{
	io_vec_free(iv);
	iv->iovec = iovec;
	iv->nr = nr;
}

/*
 This function io_vec_alloc_cache_vec_kasan allocates memory for an I/O vector and initializes it. 
 It is used to create a new I/O vector for use with requests.
*/
static inline void io_alloc_cache_vec_kasan(struct iou_vec *iv)
{
	if (IS_ENABLED(CONFIG_KASAN))
		io_vec_free(iv);
}

#endif
