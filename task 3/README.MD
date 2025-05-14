Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
|io_ev_fd | io_uring/eventfd.c | atomic_t, eventfd_ctx, int, rcu_head, refcount_t, unsigned | io_eventfd_free | io_uring/eventfd.c | local variable , function parameter
| |  |  | io_eventfd_put | io_uring/eventfd.c | function parameter
| |  |  | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| |  |  | io_eventfd_release | io_uring/eventfd.c | function parameter
| |  |  | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| |  |  | io_eventfd_trigger | io_uring/eventfd.c |  local variable
| |  |  | io_eventfd_grab | io_uring/eventfd.c | function parameter, local variable
| |  |  | io_eventfd_signal | io_uring/eventfd.c | local variable
| |  |  | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| |  |  | io_eventfd_register | io_uring/eventfd.c | local variable , function parameter
| |  |  | io_eventfd_unregister | io_uring/eventfd.c | local variable , function parameter
|io_fadvise | io_uring/advise.c | file, u32, u64 | io_fadvise_force_async | io_uring/advise.c | function parameter
| |  |  | io_fadvise_prep | io_uring/advise.c | local variable
| |  |  | io_fadvise | io_uring/advise.c | local variable
|io_madvise | io_uring/advise.c | file, u32, u64 | io_madvise_prep | io_uring/advise.c | local variable , function parameter
| |  |  | io_madvise | io_uring/advise.c | local variable , function parameter
|io_cancel | io_uring/cancel.c | file, s32, u32, u64, u8 | io_async_cancel_prep | io_uring/cancel.c | local variable , function parameter
| |  |  | io_async_cancel | io_uring/cancel.c | local variable , function parameter
|io_cancel_data | io_uring/cancel.h | io_ring_ctx, union {u64, file}, u8, u32, int | io_try_cancel | io_uring/cancel.h | function parameter
| |  |  | io_cancel_req_match | io_uring/cancel.h | function parameter
| |  |  | io_cancel_cb        | io_uring/cancel.c | local variable
| |  |  | io_async_cancel_one | io_uring/cancel.c | function parameter
| |  |  | io_try_cancel       | io_uring/cancel.c | function parameter
| |  |  | io_async_cancel       | io_uring/cancel.c | function parameter
| |  |  | __io_sync_cancel       | io_uring/cancel.c | function parameter
| |  |  | io_sync_cancel       | io_uring/cancel.c | local variable
| |  |  | io_cancel_remove       | io_uring/cancel.c | function parameter
| |  |  | io_futex_cancel | io_uring/futex.c | function parameter
| |  |  | io_futex_cancel | io_uring/futex.h | function parameter
| |  |  | __io_poll_cancel | io_uring/poll.c | function parameter
| |  |  | io_poll_cancel | io_uring/poll.c | function parameter
| |  |  | io_poll_cancel | io_uring/poll.h | function parameter
| |  |  | io_poll_remove | io_uring/poll.c | local variable
| |  |  | if | io_uring/timeout.c | local variable
| |  |  | io_timeout_cancel | io_uring/timeout.h | function parameter
| |  |  | io_waitid_cancel | io_uring/waitid.c | function parameter
| |  |  | io_waitid_cancel | io_uring/waitid.h | function parameter
|io_epoll | io_uring/epoll.c | epoll_event, file, int | io_epoll_ctl_prep | io_uring/epoll.c | local variable, function parameter
| |  |  | io_epoll_ctl | io_uring/epoll.c | local variable,function parameter
|io_epoll_wait | io_uring/epoll.c | __user, file, int | io_epoll_wait_prep | io_uring/epoll.c | local variable,function parameter
| |  |  | io_epoll_wait | io_uring/epoll.c | local variable, function parameter
|io_rename | io_uring/fs.c | file, filename, int | io_renameat_prep | io_uring/fs.c | local variable, function parameter
| |  |  | io_renameat | io_uring/fs.c | local variable, function parameter
| |  |  | io_renameat_cleanup | io_uring/fs.c | local variable, function parameter
|io_unlink | io_uring/fs.c | file, filename, int | io_unlinkat_prep | io_uring/fs.c | local variable, function paramter
| |  |  | io_unlinkat | io_uring/fs.c | local variable, function paramter
| |  |  | io_unlinkat_cleanup | io_uring/fs.c | local variable, function paramter
|io_mkdir | io_uring/fs.c | file, filename, int, umode_t | io_mkdirat_prep | io_uring/fs.c | local variable, function paramter
| |  |  | io_mkdirat | io_uring/fs.c | local variable, function paramter
| |  |  | io_mkdirat_cleanup | io_uring/fs.c | local variable, function paramter
|io_link | io_uring/fs.c | file, filename, int | io_symlinkat_prep | io_uring/fs.c | local variable, function paramter
| |  |  | io_symlinkat | io_uring/fs.c | local variable, function paramter
| |  |  | io_linkat_prep | io_uring/fs.c | local variable, function paramter
| |  |  | io_linkat | io_uring/fs.c | local variable, function paramter
| |  |  | io_link_cleanup | io_uring/fs.c | local variable, function paramter
|io_futex | io_uring/futex.c | __user, file | io_futexv_complete | io_uring/futex.c | local variable , function parameter
| |  |  | io_futexv_claim | io_uring/futex.c | function parameter
| |  |  | __io_futex_cancel | io_uring/futex.c | local variable , function parameter
| |  |  | io_futex_prep | io_uring/futex.c | local variable , function parameter
| |  |  | io_futex_wakev_fn | io_uring/futex.c | local variable , function parameter
| |  |  | io_futexv_prep | io_uring/futex.c | local variable , function parameter
| |  |  | io_futex_wake_fn | io_uring/futex.c | local variable ,  function parameter
| |  |  | io_futexv_wait | io_uring/futex.c | local variable , function parameter
| |  |  | io_futex_wait | io_uring/futex.c | local variable , function parameter
| |  |  | io_futex_wake | io_uring/futex.c | local variable , function parameter
|io_futex_data | io_uring/futex.c | futex_q, io_kiocb | __io_futex_cancel | io_uring/futex.c | local variable
| |  |  | io_futex_cache_init | io_uring/futex.c | function parameter
| |  |  | io_futex_wake_fn | io_uring/futex.c | local variable, function parameter
| |  |  | io_futex_wait | io_uring/futex.c | local variable
|io_worker | io_uring/io-wq.c | callback_head, completion, delayed_work, hlist_nulls_node, int, io_wq, io_wq_acct, io_wq_work, list_head, long, raw_spinlock_t, rcu_head, refcount_t, task_struct | io_wq_dec_running | io_uring/io-wq.c | function parameter
| |  |  | io_worker_get | io_uring/io-wq.c | function parameter
| |  |  | io_worker_release | io_uring/io-wq.c | function parameter
| |  |  | io_wq_worker_stopped | io_uring/io-wq.c | local variable
| |  |  | io_worker_cancel_cb | io_uring/io-wq.c | function parameter
| |  |  | io_task_worker_match | io_uring/io-wq.c | local variable
| |  |  | io_worker_exit | io_uring/io-wq.c | function parameter
| |  |  | __io_acct_run_queue | io_uring/io-wq.c | local variable
| |  |  | io_wq_inc_running | io_uring/io-wq.c | function parameter
| |  |  | create_worker_cb | io_uring/io-wq.c | local variable
| |  |  | io_queue_worker_create | io_uring/io-wq.c | function parameter
| |  |  | __io_worker_busy | io_uring/io-wq.c | function parameter
| |  |  | io_assign_current_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_worker | io_uring/io-wq.c | local variable
| |  |  | io_wq_worker_running | io_uring/io-wq.c | local variable
| |  |  | io_wq_worker_sleeping | io_uring/io-wq.c | local variable
| |  |  | io_init_new_worker | io_uring/io-wq.c | function parameter
| |  |  | io_should_retry_thread | io_uring/io-wq.c | function parameter
| |  |  | queue_create_worker_retry | io_uring/io-wq.c | function parameter
| |  |  | create_worker_cont | io_uring/io-wq.c | local variable
| |  |  | io_workqueue_create | io_uring/io-wq.c | local variable
| |  |  | create_io_worker | io_uring/io-wq.c | local variable
| |  |  | io_wq_worker_wake | io_uring/io-wq.c | function parameter
| |  |  | __io_wq_worker_cancel | io_uring/io-wq.c | function parameter
| |  |  | io_wq_worker_cancel | io_uring/io-wq.c | function parameter
| |  |  | io_task_work_match | io_uring/io-wq.c | local variable
| |  |  | io_wq_cancel_tw_create | io_uring/io-wq.c | local variable
| |  |  | io_wq_worker_affinity | io_uring/io-wq.c | function parameter
|io_wq_acct | io_uring/io-wq.c | atomic_t, hlist_nulls_head, io_wq_work_list, list_head, long, raw_spinlock_t, unsigned | create_io_worker | io_uring/io-wq.c | function parameter
| |  |  | io_acct_cancel_pending_work | io_uring/io-wq.c | function parameter
| |  |  | io_worker_cancel_cb | io_uring/io-wq.c | local variable
| |  |  | io_worker_exit | io_uring/io-wq.c | local variable
| |  |  | __io_acct_run_queue | io_uring/io-wq.c | function parameter
| |  |  | io_wq_create_worker | io_uring/io-wq.c | function parameter
| |  |  | io_wq_inc_running | io_uring/io-wq.c | local variable
| |  |  | create_worker_cb | io_uring/io-wq.c | local variable
| |  |  | io_queue_worker_create | io_uring/io-wq.c | function parameter
| |  |  | io_wq_dec_running | io_uring/io-wq.c | local variable
| |  |  | __io_worker_busy | io_uring/io-wq.c | function parameter
| |  |  | io_wq_worker | io_uring/io-wq.c | local variable
| |  |  | io_init_new_worker | io_uring/io-wq.c | function parameter
| |  |  | create_worker_cont | io_uring/io-wq.c | local variable
| |  |  | io_workqueue_create | io_uring/io-wq.c | local variable
| |  |  | io_wq_insert_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_enqueue | io_uring/io-wq.c | local variable
| |  |  | io_wq_remove_pending | io_uring/io-wq.c | function parameter
| |  |  | io_wq_cancel_pending_work | io_uring/io-wq.c | local variable
| |  |  | io_acct_cancel_running_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_hash_wake | io_uring/io-wq.c | local variable
| |  |  | io_wq_max_workers | io_uring/io-wq.c | local variable
|io_wq | io_uring/io-wq.c | atomic_t, completion, cpumask_var_t, free_work_fn, hlist_node, io_wq_hash, io_wq_work_fn, long, task_struct, wait_queue_entry | create_io_worker | io_uring/io-wq.c | function parameter
| |  |  | io_acct_cancel_pending_work | io_uring/io-wq.c | function parameter, local variable
| |  |  | io_wq_cancel_tw_create | io_uring/io-wq.c | function parameter
| |  |  | io_worker_ref_put | io_uring/io-wq.c | function parameter
| |  |  | io_worker_cancel_cb | io_uring/io-wq.c | local variable
| |  |  | io_worker_exit | io_uring/io-wq.c | local variable
| |  |  | io_wq_create_worker | io_uring/io-wq.c | function parameter
| |  |  | create_worker_cb | io_uring/io-wq.c | local variable
| |  |  | io_queue_worker_create | io_uring/io-wq.c | local variable
| |  |  | io_wq_dec_running | io_uring/io-wq.c | local variable
| |  |  | io_wait_on_hash | io_uring/io-wq.c | function parameter
| |  |  | wq_list_for_each | io_uring/io-wq.c | local variable
| |  |  | io_assign_current_work | io_uring/io-wq.c | local variable
| |  |  | io_wq_worker | io_uring/io-wq.c | local variable
| |  |  | io_init_new_worker | io_uring/io-wq.c | function parameter
| |  |  | create_worker_cont | io_uring/io-wq.c | local variable
| |  |  | io_run_cancel | io_uring/io-wq.c | function parameter
| |  |  | io_wq_insert_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_enqueue | io_uring/io-wq.c | function parameter
| |  |  | io_wq_enqueue | io_uring/io-wq.h | function parameter
| |  |  | io_wq_remove_pending | io_uring/io-wq.c | function parameter, local variable
| |  |  | io_wq_cancel_pending_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_cancel_running_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_cancel_cb | io_uring/io-wq.c | function parameter
| |  |  | io_wq_cancel_cb | io_uring/io-wq.h | function parameter
| |  |  | io_wq_hash_wake | io_uring/io-wq.c | local variable
| |  |  | io_wq_exit_start | io_uring/io-wq.c | function parameter
| |  |  | io_wq_exit_start | io_uring/io-wq.h | function parameter
| |  |  | io_wq_exit_workers | io_uring/io-wq.c | function parameter
| |  |  | io_wq_destroy | io_uring/io-wq.c | function parameter
| |  |  | io_wq_put_and_exit | io_uring/io-wq.c | function parameter
| |  |  | io_wq_put_and_exit | io_uring/io-wq.h | function parameter
| |  |  | __io_wq_cpu_online | io_uring/io-wq.c | function parameter
| |  |  | io_wq_cpu_online | io_uring/io-wq.c | local variable
| |  |  | io_wq_cpu_offline | io_uring/io-wq.c | local variable
| |  |  | io_wq_max_workers | io_uring/io-wq.c | function parameter
| |  |  | io_wq_max_workers | io_uring/io-wq.h | function parameter
| |  |  | wq_list_del | io_uring/slist.h | local variable
| |  |  | io_uring_clean_tctx | io_uring/tctx.c | local variable
|io_cb_cancel_data | io_uring/io-wq.c | bool, int, void, work_cancel_fn | io_acct_cancel_pending_work | io_uring/io-wq.c | function parameter
| |  |  | if | io_uring/io-wq.c | local variable
| |  |  | io_wq_enqueue | io_uring/io-wq.c | local variable
| |  |  | __io_wq_worker_cancel | io_uring/io-wq.c | function parameter
| |  |  | io_wq_worker_cancel | io_uring/io-wq.c | local variable
| |  |  | io_wq_cancel_pending_work | io_uring/io-wq.c | function parameter
| |  |  | io_acct_cancel_running_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_cancel_running_work | io_uring/io-wq.c | function parameter
| |  |  | io_wq_cancel_cb | io_uring/io-wq.c | local variable
| |  |  | io_wq_destroy | io_uring/io-wq.c | local variable
|online_data | io_uring/io-wq.c | bool, int | io_wq_worker_affinity | io_uring/io-wq.c | local variable
| |  |  | __io_wq_cpu_online | io_uring/io-wq.c | local variable
|io_wq_hash | io_uring/io-wq.h | long, refcount_t, wait_queue_head | io_wq_put_hash | io_uring/io-wq.h | function parameter, local variable
|io_defer_entry | io_uring/io_uring.c | io_kiocb, list_head, u32 | io_queue_deferred | io_uring/io_uring.c | local variable
| |  |  | io_get_sequence | io_uring/io_uring.c | local variable
| |  |  | io_cancel_defer_files | io_uring/io_uring.c | local variable
|ext_arg | io_uring/io_uring.c | __user, bool, ktime_t, size_t, timespec64 | __io_cqring_wait_schedule | io_uring/io_uring.c | function parameter
| |  |  | io_cqring_wait_schedule | io_uring/io_uring.c | function parameter
| |  |  | io_cqring_wait | io_uring/io_uring.c | function parameter
| |  |  | io_get_ext_arg | io_uring/io_uring.c | function parameter
| |  |  | if | io_uring/io_uring.c | local variable
|io_tctx_exit | io_uring/io_uring.c | callback_head, completion, io_ring_ctx | io_tctx_exit_cb | io_uring/io_uring.c | local variable
| |  |  | io_ring_exit_work | io_uring/io_uring.c | local variable
|io_task_cancel | io_uring/io_uring.c | bool, io_uring_task | io_cancel_task_cb | io_uring/io_uring.c | local variable
| |  |  | io_uring_try_cancel_requests | io_uring/io_uring.c | local variable
|io_wait_queue | io_uring/io_uring.h | bool, hrtimer, int, io_ring_ctx, ktime_t, unsigned, wait_queue_entry | io_should_wake | io_uring/io_uring.h | function parameter
| |  |  | io_napi_busy_loop_should_end | io_uring/napi.c | local variable
| |  |  | io_napi_blocking_busy_loop | io_uring/napi.c | function parameter
| |  |  | __io_napi_busy_loop | io_uring/napi.c | function parameter
| |  |  | __io_napi_busy_loop | io_uring/napi.h | function parameter
| |  |  | io_napi_busy_loop | io_uring/napi.h | function parameter
| io_ev_fd                 | io_uring/eventfd.c   | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head                                                                                                           | io_eventfd_free                  | io_uring/eventfd.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_eventfd_put                   | io_uring/eventfd.c   | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_eventfd_do_signal             | io_uring/eventfd.c   | local variable, function parameter |
|                          |                      |                                                                                                                                                                   | __io_eventfd_signal              | io_uring/eventfd.c   | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_eventfd_grab                  | io_uring/eventfd.c   | return value, local variable       |
|                          |                      |                                                                                                                                                                   | io_eventfd_signal                | io_uring/eventfd.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_eventfd_flush_signal          | io_uring/eventfd.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_eventfd_register              | io_uring/eventfd.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_eventfd_unregister            | io_uring/eventfd.c   | function parameter                 |
| io_provide_buf           | io_uring/kbuf.c      | __u16, __u32, __u64, file                                                                                                                                         | io_remove_buffers_prep           | io_uring/kbuf.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_remove_buffers                | io_uring/kbuf.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_provide_buffers_prep          | io_uring/kbuf.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_add_buffers                   | io_uring/kbuf.c      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_provide_buffers               | io_uring/kbuf.c      | local variable                     |
| io_buffer_list           | io_uring/kbuf.h      | io_uring_buf_ring, list_head                                                                                                                                      | io_kbuf_commit                   | io_uring/kbuf.h      | function parameter                 |
| buf_sel_arg              | io_uring/kbuf.h      | iovec, short, size_t                                                                                                                                              | io_buffers_select                | io_uring/kbuf.h      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_buffers_peek                  | io_uring/kbuf.h      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_send_select_buffer            | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recv_buf_select               | io_uring/net.c       | local variable                     |
| io_msg                   | io_uring/msg_ring.c  | callback_head, file, u32, u64                                                                                                                                     | io_msg_ring_cleanup              | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_msg_data_remote               | io_uring/msg_ring.c  | function parameter                 |
|                          |                      |                                                                                                                                                                   | __io_msg_ring_data               | io_uring/msg_ring.c  | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_msg_ring_data                 | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_msg_grab_file                 | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_msg_install_complete          | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_msg_tw_fd_complete            | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_msg_fd_remote                 | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_msg_send_fd                   | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_msg_ring_prep               | io_uring/msg_ring.c  | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_msg_ring                      | io_uring/msg_ring.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_uring_sync_msg_ring           | io_uring/msg_ring.c  | local variable                     |
| io_napi_entry            | io_uring/napi.c      | hlist_node, int, list_head, long, rcu_head                                                                                                                        | __io_napi_add_id                 | io_uring/napi.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_napi_del_id                 | io_uring/napi.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_napi_remove_stale           | io_uring/napi.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_napi_busy_loop_should_end     | io_uring/napi.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_napi_free                     | io_uring/napi.c      | local variable                     |
| io_shutdown              | io_uring/net.c       | file, int                                                                                                                                                         | io_shutdown_prep                 | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_shutdown                      | io_uring/net.c       | local variable                     |
| io_accept                | io_uring/net.c       | __user, file, int, long, u32                                                                                                                                      | io_accept_prep                   | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_accept                        | io_uring/net.c       | local variable                     |
| io_socket                | io_uring/net.c       | file, int, long, u32                                                                                                                                              | io_socket_prep                   | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_socket                        | io_uring/net.c       | local variable                     |
| io_connect               | io_uring/net.c       | __user, bool, file, int                                                                                                                                           | io_connect_prep                  | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_connect                       | io_uring/net.c       | local variable                     |
| io_bind                  | io_uring/net.c       | file, int                                                                                                                                                         | io_bind_prep                     | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_bind                          | io_uring/net.c       | local variable                     |
| io_listen                | io_uring/net.c       | file, int                                                                                                                                                         | io_listen_prep                   | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_listen                        | io_uring/net.c       | local variable                     |
| io_sr_msg                | io_uring/net.c       | __user, file                                                                                                                                                      | io_mshot_prep_retry              | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_compat_msg_copy_hdr           | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_msg_copy_hdr                  | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send_setup                    | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_sendmsg_setup                 | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_sendmsg_prep                  | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send_finish                   | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_sendmsg                       | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send_select_buffer            | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send                          | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recvmsg_prep_setup            | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recvmsg_prep                  | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recv_finish                   | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recvmsg_prep_multishot        | io_uring/net.c       | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_recvmsg_multishot             | io_uring/net.c       | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_recvmsg                       | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recv_buf_select               | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recv                          | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send_zc_cleanup               | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send_zc_prep                  | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send_zc_import                | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_send_zc                       | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_sendmsg_zc                    | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_sendrecv_fail                 | io_uring/net.c       | local variable                     |
| io_recvzc                | io_uring/net.c       | file, io_zcrx_ifq, u16, u32, unsigned                                                                                                                             | io_recvzc_prep                   | io_uring/net.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_recvzc                        | io_uring/net.c       | local variable                     |
| io_recvmsg_multishot_hdr | io_uring/net.c       | io_uring_recvmsg_out, sockaddr_storage                                                                                                                            | io_recvmsg_multishot             | io_uring/net.c       | local variable                     |
| io_nop                   | io_uring/nop.c       | file, int                                                                                                                                                         | io_nop_prep                      | io_uring/nop.c       | local variable                     |
|                          |                      |                                                                                                                                                                   | io_nop                           | io_uring/nop.c       | local variable                     |
| io_notif_data            | io_uring/notif.h     | bool, file, io_notif_data, ubuf_info, unsigned                                                                                                                    | io_kiocb_to_cmd                  | io_uring/notif.h     | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_notif_account_mem             | io_uring/notif.h     | local variable                     |
| io_issue_def             | io_uring/opdef.h     | short                                                                                                                                                             | io_arm_poll_handler              | io_uring/poll.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_import_rw_buffer            | io_uring/rw.c        | local variable                     |
| io_open                  | io_uring/openclose.c | file, filename, int, long, open_how, u32                                                                                                                          | io_openat_force_async            | io_uring/openclose.c | function parameter                 |
|                          |                      |                                                                                                                                                                   | __io_openat_prep                 | io_uring/openclose.c | local variable                     |
|                          |                      |                                                                                                                                                                   | io_openat_prep                   | io_uring/openclose.c | local variable                     |
|                          |                      |                                                                                                                                                                   | io_openat2_prep                  | io_uring/openclose.c | local variable                     |
|                          |                      |                                                                                                                                                                   | io_openat2                       | io_uring/openclose.c | local variable                     |
|                          |                      |                                                                                                                                                                   | io_open_cleanup                  | io_uring/openclose.c | local variable                     |
| io_close                 | io_uring/openclose.c | file, int, u32                                                                                                                                                    | io_close_fixed                   | io_uring/openclose.c | local variable                     |
|                          |                      |                                                                                                                                                                   | io_close_prep                    | io_uring/openclose.c | local variable                     |
|                          |                      |                                                                                                                                                                   | io_close                         | io_uring/openclose.c | local variable                     |
| io_fixed_install         | io_uring/openclose.c | file, int                                                                                                                                                         | io_install_fixed_fd_prep         | io_uring/openclose.c | local variable                     |
|                          |                      |                                                                                                                                                                   | io_install_fixed_fd              | io_uring/openclose.c | local variable                     |
| io_poll_update           | io_uring/poll.c      | __poll_t, bool, file, u64                                                                                                                                         | io_poll_remove_prep              | io_uring/poll.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_poll_remove                   | io_uring/poll.c      | local variable                     |
| io_poll_table            | io_uring/poll.c      | __poll_t, bool, int, io_kiocb, poll_table_struct                                                                                                                  | __io_queue_proc                  | io_uring/poll.c      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_poll_queue_proc               | io_uring/poll.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_poll_can_finish_inline        | io_uring/poll.c      | function parameter                 |
|                          |                      |                                                                                                                                                                   | __io_arm_poll_handler            | io_uring/poll.c      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_async_queue_proc              | io_uring/poll.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_arm_poll_handler              | io_uring/poll.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_poll_add                      | io_uring/poll.c      | local variable                     |
| io_ring_ctx_rings        | io_uring/register.c  | io_mapped_region, io_rings, io_uring_sqe                                                                                                                          | io_register_free_rings           | io_uring/register.c  | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_register_resize_rings         | io_uring/register.c  | local variable                     |
| io_rsrc_update           | io_uring/rsrc.c      | file, u32, u64                                                                                                                                                    | io_files_update_prep             | io_uring/rsrc.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_files_update_with_index_alloc | io_uring/rsrc.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_files_update                  | io_uring/rsrc.c      | local variable                     |
| io_rsrc_node             | io_uring/rsrc.h      | char, int, io_mapped_ubuf, long, u64                                                                                                                              | io_free_rsrc_node                | io_uring/rsrc.h      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_put_rsrc_node                 | io_uring/rsrc.h      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_reset_rsrc_node               | io_uring/rsrc.h      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_req_assign_rsrc_node          | io_uring/rsrc.h      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_req_assign_buf_node           | io_uring/rsrc.h      | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_splice_cleanup                | io_uring/splice.c    | local variable                     |
| io_imu_folio_data        | io_uring/rsrc.h      | int                                                                                                                                                               | io_check_coalesce_buffer         | io_uring/rsrc.h      | function parameter                 |
| io_rw                    | io_uring/rw.c        | kiocb, rwf_t, u32, u64                                                                                                                                            | io_iov_compat_buffer_select_prep | io_uring/rw.c        | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_iov_buffer_select_prep        | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_import_rw_buffer            | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_prep_rw_pi                    | io_uring/rw.c        | function parameter                 |
|                          |                      |                                                                                                                                                                   | __io_prep_rw                     | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_init_rw_fixed                 | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_rw_import_reg_vec             | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_rw_prep_reg_vec               | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_read_mshot_prep               | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_readv_writev_cleanup          | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_rw_should_reissue             | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_req_end_write                 | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_req_io_end                    | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_req_rw_complete               | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_complete_rw                   | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_complete_rw_iopoll            | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_rw_done                       | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | kiocb_done                       | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | loop_rw_iter                     | io_uring/rw.c        | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_async_buf_func                | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_rw_should_retry               | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_iter_do_read                  | io_uring/rw.c        | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_rw_init_file                  | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_read                        | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_read_mshot                    | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_write                         | io_uring/rw.c        | local variable                     |
|                          |                      |                                                                                                                                                                   | io_file_supports_nowait          | io_uring/rw.c        | local variable                     |
| io_splice                | io_uring/splice.c    | file, int, io_rsrc_node, loff_t, u64                                                                                                                              | __io_splice_prep                 | io_uring/splice.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_splice_cleanup                | io_uring/splice.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_tee                           | io_uring/splice.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_splice_prep                   | io_uring/splice.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_splice                        | io_uring/splice.c    | local variable                     |
| io_sq_data               | io_uring/sqpoll.h    | atomic_t, completion, int, list_head, long, mutex, pid_t, refcount_t, task_struct, u64, unsigned, wait_queue_head                                                 | io_sq_thread_stop                | io_uring/sqpoll.h    | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_sq_thread_park                | io_uring/sqpoll.h    | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_sq_thread_unpark              | io_uring/sqpoll.h    | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_put_sq_data                   | io_uring/sqpoll.h    | function parameter                 |
| io_statx                 | io_uring/statx.c     | __user, file, filename, int                                                                                                                                       | io_statx_prep                    | io_uring/statx.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_statx                         | io_uring/statx.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_statx_cleanup                 | io_uring/statx.c     | local variable                     |
| io_sync                  | io_uring/sync.c      | file, int, loff_t                                                                                                                                                 | io_sfr_prep                      | io_uring/sync.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_sync_file_range               | io_uring/sync.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_fsync_prep                    | io_uring/sync.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_fsync                         | io_uring/sync.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_fallocate_prep                | io_uring/sync.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_fallocate                     | io_uring/sync.c      | local variable                     |
| io_timeout               | io_uring/timeout.c   | file, io_kiocb, list_head, u32                                                                                                                                    | io_is_timeout_noseq              | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_timeout_finish                | io_uring/timeout.c   | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_timeout_complete              | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_flush_killed_timeouts         | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_put_req                       | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_timeout_fn                    | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_req_task_link_timeout         | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_link_timeout_fn               | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_timeout_get_clock             | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_timeout_prep                | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_timeout                       | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_queue_linked_timeout          | io_uring/timeout.c   | local variable                     |
| io_timeout_rem           | io_uring/timeout.c   | bool, file, timespec64, u32, u64                                                                                                                                  | io_timeout_remove_prep           | io_uring/timeout.c   | local variable                     |
|                          |                      |                                                                                                                                                                   | io_timeout_remove                | io_uring/timeout.c   | local variable                     |
| io_ftrunc                | io_uring/truncate.c  | file, loff_t                                                                                                                                                      | io_ftruncate_prep                | io_uring/truncate.c  | local variable                     |
|                          |                      |                                                                                                                                                                   | io_ftruncate                     | io_uring/truncate.c  | local variable                     |
| io_waitid                | io_uring/waitid.c    | __user, atomic_t, file, int, pid_t, wait_queue_head, waitid_info                                                                                                  | io_waitid_compat_copy_si         | io_uring/waitid.c    | function parameter                 |
|                          |                      |                                                                                                                                                                   | io_waitid_copy_si                | io_uring/waitid.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_waitid_complete               | io_uring/waitid.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_waitid_cancel               | io_uring/waitid.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_waitid_drop_issue_ref         | io_uring/waitid.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_waitid_cb                     | io_uring/waitid.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_waitid_wait                   | io_uring/waitid.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_waitid_prep                   | io_uring/waitid.c    | local variable                     |
|                          |                      |                                                                                                                                                                   | io_waitid                        | io_uring/waitid.c    | local variable                     |
| io_xattr                 | io_uring/xattr.c     | file, filename, kernel_xattr_ctx                                                                                                                                  | io_xattr_cleanup                 | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_getxattr_prep               | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_getxattr_prep                 | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_fgetxattr                     | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_getxattr                      | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | __io_setxattr_prep               | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_setxattr_prep                 | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_fsetxattr                     | io_uring/xattr.c     | local variable                     |
|                          |                      |                                                                                                                                                                   | io_setxattr                      | io_uring/xattr.c     | local variable                     |
| io_zcrx_args             | io_uring/zcrx.c      | io_kiocb, io_zcrx_ifq, socket, unsigned                                                                                                                           | io_zcrx_recv_skb                 | io_uring/zcrx.c      | local variable                     |
|                          |                      |                                                                                                                                                                   | io_zcrx_tcp_recvmsg              | io_uring/zcrx.c      | local variable                     |
| io_zcrx_ifq              | io_uring/zcrx.h      | device, io_ring_ctx, io_uring, io_uring_zcrx_rqe, io_zcrx_area, net_device, netdevice_tracker, spinlock_t, u32                                                    | io_zcrx_recv                     | io_uring/zcrx.h      | function parameter                 |
