# Task 2

## Source


### advise.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
|               advise.c             |      include/linux/io_uring_types.h| io_kiocb_to_cmd                | 4          |
|                                    | include/asm-generic/rwonce.h       |       READ_ONCE                | 8          |
|                                    | include/asm-generic/bug.h          | WARN_ON_ONCE                   | 2          |
|                                    | linux/mm.h                         | do_madvise                     | 1          |
|                                    | io_uring/io_uring.h,               | io_req_set_res                 | 2          |
|                                    | io_uring/advise.c                  | io_fadvise_force_async         |3           |
|                                    | include/linux/fs.h                 | vfs_fadvise                    | 1          |


### alloc_cache.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
|               alloc_cache.c        |      io_uring/alloc_cache.h        | io_alloc_cache_get         |1        |
|                                    | include/linux/slab.h               |       kvfree               | 1          |
|                                    | include/linux/slab.h          | kvmalloc_array                   | 1         |
|                                    | tools/include/linux/slab.h                         | kmalloc      |     1          |
|                                    | lib/string.c               | memset                 | 1          |


### cancel.c

| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
|               cancel.c             |      include/linux/io_uring_types.h| io_kiocb_to_cmd                | 4          |
|                                    | include/asm-generic/rwonce.h       |       READ_ONCE                | 4          |
|                                    | include/asm-generic/bug.h          | WARN_ON_ONCE                   | 2          |
|                                    | linux/mm.h                         | do_madvise                     | 1          |
|                                    | io_uring/io_uring.h,               | io_req_set_res                 | 2          |
|                                    | io_uring/advise.c                  | io_fadvise_force_async         |3           |
|                                    | include/linux/fs.h                 | vfs_fadvise                    | 1          |


### epoll.c

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| epoll.c | 	 | do_epoll_ctl | 1 |
|	 | 	 | READ_ONCE | 6 |
|	 | 	 | io_req_set_res | 2 |
|	 | 	 | ep_op_has_event | 1 |
|	 | 	 | epoll_sendevents | 1 |
|	 | 	 | req_set_fail | 2 |
|	 | 	 | copy_from_user | 1 |
|	 | 	 | u64_to_user_ptr | 2 |
|	 | 	 | io_kiocb_to_cmd | 4 |

### eventfd.c

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| eventfd.c | 	 | io_wq_current_is_worker | 1 |
|	 | 	 | rcu_dereference | 1 |
|	 | 	 | rcu_assign_pointer | 2 |
|	 | 	 | container_of | 2 |
|	 | 	 | READ_ONCE | 1 |
|	 | 	 | eventfd_ctx_fdget | 1 |
|	 | 	 | eventfd_ctx_put | 1 |
|	 | 	 | BIT | 1 |
|	 | 	 | PTR_ERR | 1 |
|	 | 	 | copy_from_user | 1 |
|	 | 	 | refcount_set | 1 |
|	 | 	 | IS_ERR | 1 |
|	 | 	 | io_eventfd_release | 2 |
|	 | 	 | io_eventfd_trigger | 1 |
|	 | 	 | atomic_fetch_or | 1 |
|	 | 	 | lockdep_is_held | 2 |
|	 | 	 | call_rcu_hurry | 1 |
|	 | 	 | atomic_set | 1 |
|	 | 	 | eventfd_signal_allowed | 1 |
|	 | 	 | rcu_read_unlock | 2 |
|	 | 	 | rcu_dereference_protected | 2 |
|	 | 	 | rcu_read_lock | 1 |
|	 | 	 | io_eventfd_put | 3 |
|	 | 	 | call_rcu | 1 |
|	 | 	 | eventfd_signal_mask | 2 |
|	 | 	 | __io_eventfd_signal | 2 |
|	 | 	 | spin_lock | 2 |
|	 | 	 | kmalloc | 1 |
|	 | 	 | spin_unlock | 2 |
|	 | 	 | kfree | 2 |
|	 | 	 | refcount_dec_and_test | 1 |
|	 | 	 | refcount_inc_not_zero | 1 |
|	 | 	 | io_eventfd_grab | 2 |

### fdinfo.c

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| fdinfo.c | 	 | spin_unlock | 1 |
|	 | 	 | seq_puts | 9 |
|	 | 	 | xa_for_each | 1 |
|	 | 	 | io_uring_show_cred | 1 |
|	 | 	 | mutex_trylock | 1 |
|	 | 	 | common_tracking_show_fdinfo | 2 |
|	 | 	 | spin_lock | 1 |
|	 | 	 | seq_file_path | 1 |
|	 | 	 | napi_show_fdinfo | 1 |
|	 | 	 | hlist_for_each_entry | 1 |
|	 | 	 | from_kuid_munged | 4 |
|	 | 	 | getrusage | 1 |
|	 | 	 | seq_printf | 32 |
|	 | 	 | min | 2 |
|	 | 	 | READ_ONCE | 6 |
|	 | 	 | io_uring_get_opcode | 1 |
|	 | 	 | seq_put_decimal_ull | 9 |
|	 | 	 | from_kgid_munged | 5 |
|	 | 	 | xa_empty | 1 |
|	 | 	 | seq_put_hex_ll | 1 |
|	 | 	 | seq_putc | 1 |
|	 | 	 | io_slot_file | 1 |
|	 | 	 | task_work_pending | 1 |
|	 | 	 | seq_user_ns | 1 |
|	 | 	 | mutex_unlock | 1 |
|	 | 	 | list_for_each_entry | 1 |

### filetable.c

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| filetable.c | 	 | io_fixed_file_set | 1 |
|	 | 	 | io_ring_submit_unlock | 1 |
|	 | 	 | io_rsrc_node_alloc | 1 |
|	 | 	 | fput | 1 |
|	 | 	 | io_is_uring_fops | 1 |
|	 | 	 | io_install_fixed_file | 1 |
|	 | 	 | unlikely | 3 |
|	 | 	 | io_file_bitmap_get | 1 |
|	 | 	 | bitmap_zalloc | 1 |
|	 | 	 | bitmap_free | 1 |
|	 | 	 | io_file_bitmap_clear | 1 |
|	 | 	 | __must_hold | 1 |
|	 | 	 | io_reset_rsrc_node | 2 |
|	 | 	 | check_add_overflow | 1 |
|	 | 	 | io_file_bitmap_set | 1 |
|	 | 	 | io_rsrc_node_lookup | 1 |
|	 | 	 | io_rsrc_data_free | 2 |
|	 | 	 | __io_fixed_fd_install | 1 |
|	 | 	 | io_file_table_set_alloc_range | 1 |
|	 | 	 | copy_from_user | 1 |
|	 | 	 | io_rsrc_data_alloc | 1 |
|	 | 	 | io_ring_submit_lock | 1 |
|	 | 	 | find_next_zero_bit | 1 || Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| fdinfo.c | 	 | spin_unlock | 1 |
|	 | 	 | seq_puts | 9 |
|	 | 	 | xa_for_each | 1 |
|	 | 	 | io_uring_show_cred | 1 |
|	 | 	 | mutex_trylock | 1 |
|	 | 	 | common_tracking_show_fdinfo | 2 |
|	 | 	 | spin_lock | 1 |
|	 | 	 | seq_file_path | 1 |
|	 | 	 | napi_show_fdinfo | 1 |
|	 | 	 | hlist_for_each_entry | 1 |
|	 | 	 | from_kuid_munged | 4 |
|	 | 	 | getrusage | 1 |
|	 | 	 | seq_printf | 32 |
|	 | 	 | min | 2 |
|	 | 	 | READ_ONCE | 6 |
|	 | 	 | io_uring_get_opcode | 1 |
|	 | 	 | seq_put_decimal_ull | 9 |
|	 | 	 | from_kgid_munged | 5 |
|	 | 	 | xa_empty | 1 |
|	 | 	 | seq_put_hex_ll | 1 |
|	 | 	 | seq_putc | 1 |
|	 | 	 | io_slot_file | 1 |
|	 | 	 | task_work_pending | 1 |
|	 | 	 | seq_user_ns | 1 |
|	 | 	 | mutex_unlock | 1 |
|	 | 	 | list_for_each_entry | 1 |

### fs.c

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| fs.c | 	 | do_rmdir | 1 |
|	 | 	 | getname_uflags | 1 |
|	 | 	 | do_unlinkat | 1 |
|	 | 	 | IS_ERR | 8 |
|	 | 	 | do_renameat2 | 1 |
|	 | 	 | PTR_ERR | 8 |
|	 | 	 | READ_ONCE | 19 |
|	 | 	 | do_symlinkat | 1 |
|	 | 	 | u64_to_user_ptr | 8 |
|	 | 	 | io_req_set_res | 5 |
|	 | 	 | do_mkdirat | 1 |
|	 | 	 | getname | 7 |
|	 | 	 | unlikely | 5 |
|	 | 	 | do_linkat | 1 |
|	 | 	 | putname | 9 |
|	 | 	 | WARN_ON_ONCE | 5 |
|	 | 	 | io_kiocb_to_cmd | 14 |

### futex.c

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| futex.c | 	 | io_req_task_complete | 1 |
|	 | 	 | io_tw_lock | 2 |
|	 | 	 | io_cache_free | 1 |
|	 | 	 | futex_flags_valid | 1 |
|	 | 	 | io_alloc_cache_free | 1 |
|	 | 	 | io_alloc_cache_init | 1 |
|	 | 	 | io_cache_alloc | 1 |
|	 | 	 | kcalloc | 1 |
|	 | 	 | u64_to_user_ptr | 2 |
|	 | 	 | io_cancel_remove | 1 |
|	 | 	 | __set_current_state | 1 |
|	 | 	 | io_kiocb_to_cmd | 8 |
|	 | 	 | io_req_set_res | 8 |
|	 | 	 | io_req_task_work_add | 3 |
|	 | 	 | hlist_del_init | 2 |
|	 | 	 | test_bit | 1 |
|	 | 	 | io_futexv_claim | 2 |
|	 | 	 | futex_validate_input | 2 |
|	 | 	 | kfree | 4 |
|	 | 	 | test_and_set_bit_lock | 1 |
|	 | 	 | unlikely | 5 |
|	 | 	 | io_cancel_remove_all | 1 |
|	 | 	 | futex2_to_flags | 1 |
|	 | 	 | hlist_add_head | 2 |
|	 | 	 | futex_wait_setup | 1 |
|	 | 	 | futex_unqueue | 1 |
|	 | 	 | futex_queue | 1 |
|	 | 	 | io_ring_submit_lock | 2 |
|	 | 	 | futex_unqueue_multiple | 1 || Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| fs.c | 	 | do_rmdir | 1 |
|	 | 	 | getname_uflags | 1 |
|	 | 	 | do_unlinkat | 1 |
|	 | 	 | IS_ERR | 8 |
|	 | 	 | do_renameat2 | 1 |
|	 | 	 | PTR_ERR | 8 |
|	 | 	 | READ_ONCE | 19 |
|	 | 	 | do_symlinkat | 1 |
|	 | 	 | u64_to_user_ptr | 8 |
|	 | 	 | io_req_set_res | 5 |
|	 | 	 | do_mkdirat | 1 |
|	 | 	 | getname | 7 |
|	 | 	 | unlikely | 5 |
|	 | 	 | do_linkat | 1 |
|	 | 	 | putname | 9 |
|	 | 	 | WARN_ON_ONCE | 5 |
|	 | 	 | io_kiocb_to_cmd | 14 |
|	 | 	 | __futex_wake_mark | 2 |
|	 | 	 | futex_wait_multiple_setup | 1 |
|	 | 	 | READ_ONCE | 6 |
|	 | 	 | container_of | 1 |
|	 | 	 | __io_futex_complete | 2 |
|	 | 	 | futex_wake | 1 |
|	 | 	 | req_set_fail | 3 |

### io_uring.c

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| io_uring.c | 	 | io_get_time | 1 |
|	 | 	 | array_index_nospec | 4 |
|	 | 	 | io_req_caches_free | 2 |
|	 | 	 | llist_reverse_order | 2 |
|	 | 	 | S_ISBLK | 1 |
|	 | 	 | spin_lock | 12 |
|	 | 	 | lockdep_assert_held | 5 |
|	 | 	 | hrtimer_cancel | 1 |
|	 | 	 | io_get_ext_arg_reg | 1 |
|	 | 	 | io_unregister_personality | 1 |
|	 | 	 | xa_for_each | 3 |
|	 | 	 | clear_bit | 2 |
|	 | 	 | memcpy | 1 |
|	 | 	 | io_uring_del_tctx_node | 1 |
|	 | 	 | hrtimer_set_expires_range_ns | 1 |
|	 | 	 | mutex_init | 2 |
|	 | 	 | __io_uring_free | 1 |
|	 | 	 | cleanup | 1 |
|	 | 	 | io_extract_req | 1 |
|	 | 	 | io_alloc_cache_free | 5 |
|	 | 	 | io_create_region | 2 |
|	 | 	 | trace_io_uring_submit_req | 1 |
|	 | 	 | percpu_ref_put | 6 |
|	 | 	 | io_cache_free | 1 |
|	 | 	 | max | 2 |
|	 | 	 | security_uring_allowed | 1 |
|	 | 	 | ktime_add_ns | 1 |
|	 | 	 | io_task_work_pending | 1 |
|	 | 	 | io_cqring_event_overflow | 3 |
|	 | 	 | in_group_p | 1 |
|	 | 	 | io_get_cqe | 1 |
|	 | 	 | llist_for_each_entry_safe | 1 |
|	 | 	 | io_sqe_buffers_unregister | 1 |
|	 | 	 | io_cqring_timer_wakeup | 1 |
|	 | 	 | io_arm_ltimeout | 2 |
|	 | 	 | percpu_ref_get | 4 |
|	 | 	 | gid_valid | 1 |
|	 | 	 | destroy_hrtimer_on_stack | 1 |
|	 | 	 | BUILD_BUG_ON | 16 |
|	 | 	 | kvfree | 2 |
|	 | 	 | io_slot_flags | 1 |
|	 | 	 | req_need_defer | 3 |
|	 | 	 | io_is_uring_fops | 2 |
|	 | 	 | io_init_fail_req | 9 |
|	 | 	 | list_empty | 9 |
|	 | 	 | io_uring_get_file | 1 |
|	 | 	 | __io_cq_lock | 2 |
|	 | 	 | io_uring_setup | 1 |
|	 | 	 | put_cred | 3 |
|	 | 	 | io_allowed_run_tw | 2 |
|	 | 	 | trace_io_uring_local_work_run | 1 |
|	 | 	 | tctx_task_work_run | 1 |
|	 | 	 | list_del_init | 2 |
|	 | 	 | rings_size | 1 |
|	 | 	 | kfree | 10 |
|	 | 	 | kzalloc | 1 |
|	 | 	 | req_ref_put | 1 |
|	 | 	 | io_uring_fill_params | 1 |
|	 | 	 | io_file_can_poll | 2 |
|	 | 	 | sizeof_field | 3 |
|	 | 	 | io_submit_sqe | 1 |
|	 | 	 | container_of | 20 |
|	 | 	 | io_fill_cqe_aux | 3 |
|	 | 	 | io_slot_file | 1 |
|	 | 	 | io_local_work_pending | 7 |
|	 | 	 | ALIGN | 1 |
|	 | 	 | hrtimer_start_expires | 1 |
|	 | 	 | req_fail_link_node | 2 |
|	 | 	 | llist_add | 2 |
|	 | 	 | io_activate_pollwq | 1 |
|	 | 	 | io_do_iopoll | 2 |
|	 | 	 | io_drain_req | 1 |
|	 | 	 | blk_finish_plug | 1 |
|	 | 	 | fput | 2 |
|	 | 	 | io_wq_put_hash | 1 |
|	 | 	 | init_task_work | 2 |
|	 | 	 | copy_to_user | 1 |
|	 | 	 | wq_list_add_tail | 1 |
|	 | 	 | io_sq_thread_park | 1 |
|	 | 	 | io_iopoll_check | 1 |
|	 | 	 | io_disarm_next | 1 |
|	 | 	 | LIST_HEAD | 1 |
|	 | 	 | trace_io_uring_file_get | 1 |
|	 | 	 | min_t | 1 |
|	 | 	 | io_req_cache_empty | 2 |
|	 | 	 | mutex_unlock | 22 |
|	 | 	 | io_kbuf_recycle | 2 |
|	 | 	 | INIT_HLIST_HEAD | 4 |
|	 | 	 | READ_ONCE | 31 |
|	 | 	 | INIT_WQ_LIST | 3 |
|	 | 	 | io_wq_worker_stopped | 1 |
|	 | 	 | schedule_delayed_work | 1 |
|	 | 	 | smp_rmb | 1 |
|	 | 	 | io_prep_async_link | 2 |
|	 | 	 | io_submit_state_start | 1 |
|	 | 	 | trace_io_uring_create | 1 |
|	 | 	 | capable | 1 |
|	 | 	 | trace_io_uring_task_work_run | 1 |
|	 | 	 | io_issue_sqe | 2 |
|	 | 	 | io_kill_timeouts | 1 |
|	 | 	 | __wq_list_for_each | 1 |
|	 | 	 | __io_cqring_events_user | 2 |
|	 | 	 | xa_init_flags | 1 |
|	 | 	 | spin_lock_init | 2 |
|	 | 	 | autoremove_wake_function | 1 |
|	 | 	 | init_waitqueue_func_entry | 1 |
|	 | 	 | try_cmpxchg | 1 |
|	 | 	 | __releases | 1 |
|	 | 	 | free_uid | 1 |
|	 | 	 | io_unregister_zcrx_ifqs | 1 |
|	 | 	 | file_inode | 3 |
|	 | 	 | BUG_ON | 2 |
|	 | 	 | prepare_to_wait | 1 |
|	 | 	 | check_add_overflow | 2 |
|	 | 	 | u64_to_user_ptr | 3 |
|	 | 	 | io_uring_optable_init | 1 |
|	 | 	 | req_ref_get | 1 |
|	 | 	 | io_alloc_hash_table | 1 |
|	 | 	 | io_uring_drop_tctx_refs | 3 |
|	 | 	 | io_uring_try_cancel_requests | 3 |
|	 | 	 | put_task_struct_many | 1 |
|	 | 	 | io_uring_add_tctx_node | 1 |
|	 | 	 | __set_current_state | 3 |
|	 | 	 | issue | 1 |
|	 | 	 | S_ISREG | 1 |
|	 | 	 | kvmalloc_array | 1 |
|	 | 	 | same_thread_group | 1 |
|	 | 	 | blk_start_plug_nr_ios | 1 |
|	 | 	 | synchronize_rcu | 1 |
|	 | 	 | io_get_cqe_overflow | 1 |
|	 | 	 | task_work_pending | 2 |
|	 | 	 | make_kgid | 1 |
|	 | 	 | roundup_pow_of_two | 2 |
|	 | 	 | io_wq_enqueue | 1 |
|	 | 	 | INIT_DELAYED_WORK | 1 |
|	 | 	 | get_task_struct | 1 |
|	 | 	 | io_req_local_work_add | 1 |
|	 | 	 | io_commit_cqring_flush | 2 |
|	 | 	 | io_init_drain | 1 |
|	 | 	 | io_region_get_ptr | 2 |
|	 | 	 | __io_run_local_work | 2 |
|	 | 	 | hrtimer_set_expires | 1 |
|	 | 	 | wake_up_state | 1 |
|	 | 	 | io_queue_sqe | 2 |
|	 | 	 | io_sqpoll_wait_sq | 1 |
|	 | 	 | set_compat_user_sigmask | 1 |
|	 | 	 | io_file_get_normal | 1 |
|	 | 	 | io_rings_free | 3 |
|	 | 	 | io_cqring_events | 2 |
|	 | 	 | init_waitqueue_head | 3 |
|	 | 	 | __acquires | 1 |
|	 | 	 | raw_spin_unlock_irq | 2 |
|	 | 	 | memset | 6 |
|	 | 	 | llist_del_all | 6 |
|	 | 	 | list_add_tail | 2 |
|	 | 	 | io_run_local_work | 4 |
|	 | 	 | struct_size | 1 |
|	 | 	 | kmem_cache_alloc_bulk | 1 |
|	 | 	 | ARRAY_SIZE | 2 |
|	 | 	 | io_napi_busy_loop | 1 |
|	 | 	 | list_rotate_left | 1 |
|	 | 	 | io_req_assign_rsrc_node | 1 |
|	 | 	 | io_poll_remove_all | 1 |
|	 | 	 | io_put_task | 1 |
|	 | 	 | __io_cqring_overflow_flush | 3 |
|	 | 	 | io_uring_try_cancel_iowq | 1 |
|	 | 	 | xa_destroy | 2 |
|	 | 	 | io_iopoll_try_reap_events | 1 |
|	 | 	 | atomic_read | 7 |
|	 | 	 | list_for_each_entry_reverse | 1 |
|	 | 	 | io_get_sequence | 1 |
|	 | 	 | xa_load | 1 |
|	 | 	 | mutex_lock | 21 |
|	 | 	 | __io_req_set_refcount | 2 |
|	 | 	 | io_futex_remove_all | 1 |
|	 | 	 | __io_run_local_work_loop | 2 |
|	 | 	 | io_req_cqe_overflow | 2 |
|	 | 	 | io_req_task_work_add | 5 |
|	 | 	 | atomic_set | 6 |
|	 | 	 | init_llist_head | 1 |
|	 | 	 | io_run_local_work_continue | 2 |
|	 | 	 | io_wq_is_hashed | 1 |
|	 | 	 | xa_init | 1 |
|	 | 	 | io_uring_allowed | 1 |
|	 | 	 | hrtimer_update_function | 1 |
|	 | 	 | io_account_cq_overflow | 1 |
|	 | 	 | __io_req_task_work_add | 1 |
|	 | 	 | security_uring_override_creds | 1 |
|	 | 	 | __io_fallback_tw | 3 |
|	 | 	 | wq_list_empty | 7 |
|	 | 	 | io_cqring_do_overflow_flush | 2 |
|	 | 	 | atomic_dec | 2 |
|	 | 	 | io_for_each_link | 4 |
|	 | 	 | io_match_task_safe | 2 |
|	 | 	 | io_move_task_work_from_local | 1 |
|	 | 	 | prep | 1 |
|	 | 	 | init_completion | 2 |
|	 | 	 | wq_has_sleeper | 1 |
|	 | 	 | set_bit | 2 |
|	 | 	 | io_wq_current_is_worker | 1 |
|	 | 	 | io_uring_sanitise_params | 1 |
|	 | 	 | get_timespec64 | 1 |
|	 | 	 | io_cqring_wait_schedule | 1 |
|	 | 	 | io_cqring_schedule_timeout | 1 |
|	 | 	 | io_req_set_refcount | 1 |
|	 | 	 | io_wq_hash_work | 1 |
|	 | 	 | io_cq_lock | 4 |
|	 | 	 | array_size | 3 |
|	 | 	 | io_clean_op | 1 |
|	 | 	 | static_branch_dec | 1 |
|	 | 	 | task_work_add | 3 |
|	 | 	 | wake_up | 3 |
|	 | 	 | mmgrab | 1 |
|	 | 	 | ERR_PTR | 2 |
|	 | 	 | trace_io_uring_cqring_wait | 1 |
|	 | 	 | list_empty_careful | 1 |
|	 | 	 | percpu_ref_exit | 2 |
|	 | 	 | io_fallback_tw | 2 |
|	 | 	 | io_queue_next | 1 |
|	 | 	 | smp_mb | 2 |
|	 | 	 | io_wq_cancel_cb | 3 |
|	 | 	 | lockdep_assert | 1 |
|	 | 	 | PTR_ERR | 2 |
|	 | 	 | kmem_cache_create | 1 |
|	 | 	 | io_futex_cache_free | 1 |
|	 | 	 | kmalloc | 2 |
|	 | 	 | io_eventfd_flush_signal | 1 |
|	 | 	 | get_cred | 1 |
|	 | 	 | __io_issue_sqe | 2 |
|	 | 	 | io_cqring_wait | 1 |
|	 | 	 | io_submit_sqes | 1 |
|	 | 	 | static_branch_inc | 1 |
|	 | 	 | get_current_cred | 1 |
|	 | 	 | current_pending_io | 1 |
|	 | 	 | io_get_ext_arg | 1 |
|	 | 	 | io_flush_timeouts | 1 |
|	 | 	 | io_alloc_cache_init | 5 |
|	 | 	 | __BUILD_BUG_VERIFY_OFFSET_SIZE | 2 |
|	 | 	 | override_creds | 1 |
|	 | 	 | io_free_batch_list | 1 |
|	 | 	 | io_rsrc_node_lookup | 1 |
|	 | 	 | io_submit_state_end | 1 |
|	 | 	 | user_access_end | 2 |
|	 | 	 | __io_uring_add_tctx_node | 1 |
|	 | 	 | io_submit_flush_completions | 4 |
|	 | 	 | io_file_get_fixed | 1 |
|	 | 	 | io_should_wake | 3 |
|	 | 	 | io_cq_unlock_post | 4 |
|	 | 	 | io_futex_cache_init | 1 |
|	 | 	 | io_uring_try_cancel_uring_cmd | 1 |
|	 | 	 | trace_io_uring_complete | 1 |
|	 | 	 | atomic_andnot | 3 |
|	 | 	 | list_cut_position | 1 |
|	 | 	 | io_ring_submit_unlock | 1 |
|	 | 	 | io_handle_tw_list | 1 |
|	 | 	 | ktime_add | 1 |
|	 | 	 | trace_io_uring_req_failed | 1 |
|	 | 	 | io_prep_linked_timeout | 2 |
|	 | 	 | io_ring_ctx_alloc | 1 |
|	 | 	 | io_wq_exit_start | 1 |
|	 | 	 | current_user | 1 |
|	 | 	 | llist_empty | 1 |
|	 | 	 | PAGE_ALIGN | 2 |
|	 | 	 | trace_io_uring_queue_async_work | 1 |
|	 | 	 | percpu_ref_kill | 1 |
|	 | 	 | BIT | 5 |
|	 | 	 | anon_inode_create_getfile | 1 |
|	 | 	 | io_run_task_work | 6 |
|	 | 	 | copy_from_user | 3 |
|	 | 	 | restore_saved_sigmask_unless | 1 |
|	 | 	 | __set_notify_signal | 1 |
|	 | 	 | req_set_fail | 2 |
|	 | 	 | INDIRECT_CALL_2 | 2 |
|	 | 	 | io_arm_poll_handler | 3 |
|	 | 	 | io_free_region | 3 |
|	 | 	 | io_kbuf_drop_legacy | 1 |
|	 | 	 | wq_stack_add_head | 1 |
|	 | 	 | io_queue_async | 1 |
|	 | 	 | wait_for_completion_interruptible | 1 |
|	 | 	 | io_uring_cancel_generic | 1 |
|	 | 	 | io_sqring_entries | 1 |
|	 | 	 | audit_uring_entry | 1 |
|	 | 	 | IS_ERR | 2 |
|	 | 	 | io_commit_sqring | 1 |
|	 | 	 | io_prep_async_work | 2 |
|	 | 	 | raw_spin_lock_init | 1 |
|	 | 	 | unlikely | 56 |
|	 | 	 | io_queue_sqe_fallback | 3 |
|	 | 	 | BUILD_BUG_SQE_ELEM_SIZE | 1 |
|	 | 	 | current_cred | 1 |
|	 | 	 | io_ring_submit_lock | 1 |
|	 | 	 | INIT_WORK | 1 |
|	 | 	 | wake_up_process | 1 |
|	 | 	 | io_uring_unreg_ringfd | 1 |
|	 | 	 | io_file_get_flags | 1 |
|	 | 	 | __io_prep_linked_timeout | 2 |
|	 | 	 | __io_cq_unlock_post | 2 |
|	 | 	 | io_get_task_refs | 1 |
|	 | 	 | check_shl_overflow | 1 |
|	 | 	 | schedule | 3 |
|	 | 	 | io_check_restriction | 1 |
|	 | 	 | io_cqring_overflow_kill | 2 |
|	 | 	 | func | 1 |
|	 | 	 | io_req_complete_defer | 3 |
|	 | 	 | io_req_put_rsrc_nodes | 1 |
|	 | 	 | io_destroy_buffers | 1 |
|	 | 	 | io_poll_wq_wake | 1 |
|	 | 	 | io_req_normal_work_add | 1 |
|	 | 	 | io_sq_thread_unpark | 1 |
|	 | 	 | min | 4 |
|	 | 	 | io_rsrc_cache_init | 1 |
|	 | 	 | time_after | 2 |
|	 | 	 | guard | 1 |
|	 | 	 | user_access_begin | 1 |
|	 | 	 | flush_delayed_work | 4 |
|	 | 	 | tctx_inflight | 3 |
|	 | 	 | io_req_find_next | 2 |
|	 | 	 | io_should_terminate_tw | 1 |
|	 | 	 | clamp | 1 |
|	 | 	 | refcount_add | 1 |
|	 | 	 | io_run_local_work_locked | 2 |
|	 | 	 | io_assign_file | 2 |
|	 | 	 | io_allocate_scq_urings | 1 |
|	 | 	 | fail | 1 |
|	 | 	 | atomic_inc | 2 |
|	 | 	 | io_free_req | 1 |
|	 | 	 | revert_creds | 1 |
|	 | 	 | trace_io_uring_cqe_overflow | 1 |
|	 | 	 | io_preinit_req | 1 |
|	 | 	 | finish_wait | 2 |
|	 | 	 | io_queue_iowq | 5 |
|	 | 	 | percpu_counter_add | 1 |
|	 | 	 | io_match_linked | 2 |
|	 | 	 | io_get_sqe | 1 |
|	 | 	 | likely | 6 |
|	 | 	 | io_req_add_to_cache | 3 |
|	 | 	 | percpu_ref_put_many | 1 |
|	 | 	 | ilog2 | 1 |
|	 | 	 | static_branch_unlikely | 1 |
|	 | 	 | timespec64_to_ktime | 1 |
|	 | 	 | io_rsrc_cache_free | 1 |
|	 | 	 | wake_up_all | 1 |
|	 | 	 | atomic_or | 8 |
|	 | 	 | wq_list_add_head | 1 |
|	 | 	 | DEFINE_WAIT | 1 |
|	 | 	 | need_resched | 4 |
|	 | 	 | io_init_req | 1 |
|	 | 	 | io_allowed_defer_tw_run | 1 |
|	 | 	 | io_queue_linked_timeout | 3 |
|	 | 	 | offsetof | 21 |
|	 | 	 | io_req_track_inflight | 1 |
|	 | 	 | io_sqring_full | 1 |
|	 | 	 | ns_capable_noaudit | 1 |
|	 | 	 | __io_cqring_events | 3 |
|	 | 	 | io_eventfd_unregister | 1 |
|	 | 	 | get_uid | 1 |
|	 | 	 | ktime_compare | 1 |
|	 | 	 | list_for_each_entry | 2 |
|	 | 	 | io_alloc_req | 1 |
|	 | 	 | percpu_counter_sub | 2 |
|	 | 	 | audit_uring_exit | 1 |
|	 | 	 | io_sq_thread_finish | 1 |
|	 | 	 | spin_unlock | 14 |
|	 | 	 | ctx_flush_and_put | 3 |
|	 | 	 | __io_arm_ltimeout | 1 |
|	 | 	 | __io_req_find_next_prep | 1 |
|	 | 	 | io_free_alloc_caches | 2 |
|	 | 	 | io_ring_add_registered_file | 1 |
|	 | 	 | wait_for_completion_interruptible_timeout | 1 |
|	 | 	 | io_shutdown_zcrx_ifqs | 1 |
|	 | 	 | set_user_sigmask | 1 |
|	 | 	 | io_ring_ctx_wait_and_kill | 2 |
|	 | 	 | __io_cqring_wait_schedule | 1 |
|	 | 	 | cond_resched | 8 |
|	 | 	 | hrtimer_setup_on_stack | 2 |
|	 | 	 | io_submit_fail_init | 1 |
|	 | 	 | io_req_task_queue | 4 |
|	 | 	 | io_uring_install_fd | 1 |
|	 | 	 | io_sqe_files_unregister | 1 |
|	 | 	 | prepare_to_wait_exclusive | 1 |
|	 | 	 | io_commit_cqring | 2 |
|	 | 	 | io_iopoll_req_issued | 1 |
|	 | 	 | alloc_workqueue | 1 |
|	 | 	 | fget | 2 |
|	 | 	 | percpu_counter_read_positive | 1 |
|	 | 	 | raw_spin_lock_irq | 2 |
|	 | 	 | percpu_counter_sum | 1 |
|	 | 	 | in_compat_syscall | 2 |
|	 | 	 | list_first_entry | 4 |
|	 | 	 | kmem_cache_alloc | 1 |
|	 | 	 | io_ring_ctx_free | 1 |
|	 | 	 | io_cqring_wake | 2 |
|	 | 	 | fd_install | 1 |
|	 | 	 | put_task_struct | 2 |
|	 | 	 | __must_hold | 11 |
|	 | 	 | trace_io_uring_defer | 1 |
|	 | 	 | io_waitid_remove_all | 1 |
|	 | 	 | set_current_state | 1 |
|	 | 	 | io_uring_create | 1 |
|	 | 	 | io_napi_free | 1 |
|	 | 	 | io_req_set_res | 3 |
|	 | 	 | io_uring_clean_tctx | 1 |
|	 | 	 | percpu_ref_get_many | 1 |
|	 | 	 | unsafe_get_user | 4 |
|	 | 	 | io_req_task_queue_fail | 4 |
|	 | 	 | io_req_defer_failed | 5 |
|	 | 	 | WRITE_ONCE | 9 |
|	 | 	 | req_ref_put_and_test_atomic | 1 |
|	 | 	 | INIT_LIST_HEAD | 7 |
|	 | 	 | req_ref_put_and_test | 1 |
|	 | 	 | test_bit | 3 |
|	 | 	 | queue_work | 1 |
|	 | 	 | io_put_kbuf | 1 |
|	 | 	 | task_sigpending | 3 |
|	 | 	 | smp_store_release | 1 |
|	 | 	 | register_sysctl_init | 1 |
|	 | 	 | WARN_ON_ONCE | 16 |
|	 | 	 | percpu_ref_init | 1 |
|	 | 	 | list_del | 1 |
|	 | 	 | mmdrop | 1 |
|	 | 	 | complete | 2 |
|	 | 	 | io_put_file | 1 |
|	 | 	 | trace_io_uring_link | 1 |
|	 | 	 | io_fill_cqe_req | 2 |
|	 | 	 | io_sq_offload_create | 1 |
|	 | 	 | io_has_work | 3 |
|	 | 	 | io_napi_init | 1 |
|	 | 	 | BUILD_BUG_SQE_ELEM | 43 |
|	 | 	 | io_validate_ext_arg | 1 |
|	 | 	 | io_queue_deferred | 1 |
|	 | 	 | io_eventfd_signal | 1 |
|	 | 	 | poll_wait | 1 |
|	 | 	 | io_tw_lock | 3 |
|	 | 	 | io_cancel_defer_files | 1 |
|	 | 	 | kmem_cache_free | 1 |
|	 | 	 | io_req_complete_post | 1 |
|	 | 	 | get_unused_fd_flags | 1 |


### Headers

### advise.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|



### alloc_cache.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| alloc_cache.h | 	 | kfree | 1 |
|	 | 	 | kasan_mempool_unpoison_object | 1 |
|	 | 	 | io_cache_alloc_new | 2 |
|	 | 	 | memset | 1 |
|	 | 	 | kasan_mempool_poison_object | 1 |
|	 | 	 | io_alloc_cache_put | 1 |
|	 | 	 | io_alloc_cache_get | 1 |
|	 | 	 | io_alloc_cache_init | 1 |


### cancel.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| cancel.h | 	 | io_cancel_remove | 1 |




### epoll.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|


### eventfd.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|



### fdinfo.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|


### filetable.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| filetable.h | 	 | __set_bit | 1 |
|	 | 	 | WARN_ON_ONCE | 2 |
|	 | 	 | __clear_bit | 1 |
|	 | 	 | test_bit | 2 |
|	 | 	 | io_file_get_flags | 1 |



### fs.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|


### futex.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|



### io_uring.h

| Source | Library | Function Utilized | Times Used |
|--------|---------|-------------------|------------|
| io_uring.h | 	 | __must_hold | 1 |
|	 | 	 | __io_alloc_req_refill | 1 |
|	 | 	 | READ_ONCE | 2 |
|	 | 	 | __io_submit_flush_completions | 1 |
|	 | 	 | mutex_lock | 1 |
|	 | 	 | io_req_task_work_add | 1 |
|	 | 	 | wq_stack_extract | 1 |
|	 | 	 | in_task | 1 |
|	 | 	 | __set_current_state | 3 |
|	 | 	 | io_extract_req | 1 |
|	 | 	 | test_bit | 1 |
|	 | 	 | __io_req_task_work_add | 1 |
|	 | 	 | poll_to_key | 2 |
|	 | 	 | smp_store_release | 1 |
|	 | 	 | WARN_ON_ONCE | 1 |
|	 | 	 | __io_commit_cqring_flush | 1 |
|	 | 	 | io_req_set_res | 1 |
|	 | 	 | wq_list_empty | 1 |
|	 | 	 | memcpy | 2 |
|	 | 	 | wq_list_add_tail | 1 |
|	 | 	 | trace_io_uring_complete_enabled | 1 |
|	 | 	 | resume_user_mode_work | 1 |
|	 | 	 | io_lockdep_assert_cq_locked | 2 |
|	 | 	 | smp_load_acquire | 1 |
|	 | 	 | io_cache_alloc | 1 |
|	 | 	 | atomic_read | 1 |
|	 | 	 | kmalloc | 1 |
|	 | 	 | mutex_unlock | 1 |
|	 | 	 | min | 1 |
|	 | 	 | likely | 2 |
|	 | 	 | percpu_ref_is_dying | 1 |
|	 | 	 | io_req_cache_empty | 1 |
|	 | 	 | test_thread_flag | 2 |
|	 | 	 | io_cqe_cache_refill | 1 |
|	 | 	 | unlikely | 9 |
|	 | 	 | ktime_get | 1 |
|	 | 	 | ktime_get_with_offset | 1 |
|	 | 	 | fput | 1 |
|	 | 	 | file_can_poll | 1 |
|	 | 	 | io_get_cqe_overflow | 1 |
|	 | 	 | IS_ENABLED | 1 |
|	 | 	 | wq_has_sleeper | 2 |
|	 | 	 | task_work_run | 1 |
|	 | 	 | __wake_up | 2 |
|	 | 	 | io_local_work_pending | 2 |
|	 | 	 | lockdep_assert | 2 |
|	 | 	 | llist_empty | 1 |
|	 | 	 | memset | 1 |
|	 | 	 | io_task_refs_refill | 1 |
|	 | 	 | container_of | 1 |
|	 | 	 | lockdep_assert_held | 7 |
|	 | 	 | task_work_pending | 2 |
|	 | 	 | clear_notify_signal | 1 |
|	 | 	 | io_get_cqe | 2 |
|	 | 	 | tctx_task_work_run | 1 |
|	 | 	 | trace_io_uring_complete | 1 |