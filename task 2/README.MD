# Task 2

## Source


### advise.c
| Source File | Library/Header                 | Function               | Times Used |
| ----------- | ------------------------------ | ---------------------- | ---------- |
| advise.c    | include/linux/io_uring_types.h | io_kiocb_to_cmd        | 4          |
|             | include/asm-generic/rwonce.h   | READ_ONCE              | 8          |
|             | include/asm-generic/bug.h      | WARN_ON_ONCE           | 2          |
|             | linux/mm.h                     | do_madvise             | 1          |
|             | io_uring/io_uring.h,           | io_req_set_res         | 2          |
|             | io_uring/advise.c              | io_fadvise_force_async | 3          |
|             | include/linux/fs.h             | vfs_fadvise            | 1          |


### alloc_cache.c
| Source File   | Library/Header             | Function           | Times Used |
| ------------- | -------------------------- | ------------------ | ---------- |
| alloc_cache.c | io_uring/alloc_cache.h     | io_alloc_cache_get | 1          |
|               | include/linux/slab.h       | kvfree             | 1          |
|               | include/linux/slab.h       | kvmalloc_array     | 1          |
|               | tools/include/linux/slab.h | kmalloc            | 1          |
|               | lib/string.c               | memset             | 1          |


### cancel.c

| Source File | Library/Header                 | Function               | Times Used |
| ----------- | ------------------------------ | ---------------------- | ---------- |
| cancel.c    | include/linux/io_uring_types.h | io_kiocb_to_cmd        | 4          |
|             | include/asm-generic/rwonce.h   | READ_ONCE              | 4          |
|             | include/asm-generic/bug.h      | WARN_ON_ONCE           | 2          |
|             | linux/mm.h                     | do_madvise             | 1          |
|             | io_uring/io_uring.h,           | io_req_set_res         | 2          |
|             | io_uring/advise.c              | io_fadvise_force_async | 3          |
|             | include/linux/fs.h             | vfs_fadvise            | 1          |


### epoll.c

| Source  | Library                      | Function Utilized | Times Used |
| ------- | ---------------------------- | ----------------- | ---------- |
| epoll.c | fs/eventpoll.c               | do_epoll_ctl      | 1          |
|         | include/asm-generic/rwonce.h | READ_ONCE         | 6          |
|         | io_uring/io_uring.h          | io_req_set_res    | 2          |
|         | include/linux/eventpoll.h    | ep_op_has_event   | 1          |
|         | fs/eventpoll.c               | epoll_sendevents  | 1          |
|         | io_uring/io_uring.h          | req_set_fail      | 2          |
|         | include/linux/uaccess.h      | copy_from_user    | 1          |
|         | include/linux/kernel.h       | u64_to_user_ptr   | 2          |
|         | include/linux/io_uring       | io_kiocb_to_cmd   | 4          |

### eventfd.c

| Source    | Library                                              | Function Utilized         | Times Used |
| --------- | ---------------------------------------------------- | ------------------------- | ---------- |
| eventfd.c | io_uring/io-wq.h                                     | io_wq_current_is_worker   | 1          |
|           | include/linux/rcupdate.h                             | rcu_dereference           | 1          |
|           | include/linux/rcupdate.h                             | rcu_assign_pointer        | 2          |
|           | include/linux/container_of.h                         | container_of              | 2          |
|           | include/asm-generic/rwonce.h                         | READ_ONCE                 | 1          |
|           | fs/eventfd.c                                         | eventfd_ctx_fdget         | 1          |
|           | fs/eventfd.c                                         | eventfd_ctx_put           | 1          |
|           | include/vdso/bits.h                                  | BIT                       | 1          |
|           | include/linux/err.h                                  | PTR_ERR                   | 1          |
|           | include/linux/uaccess.h                              | copy_from_user            | 1          |
|           | include/linux/refcount.h                             | refcount_set              | 1          |
|           | fs/bcachefs/trace.h                                  | IS_ERR                    | 1          |
|           | io_uring/eventfd.c                                   | io_eventfd_release        | 2          |
|           | io_uring/eventfd.c                                   | io_eventfd_trigger        | 1          |
|           | include/linux/atomic/atomic-instrumented.h           | atomic_fetch_or           | 1          |
|           | include/linux/lockdep.h                              | lockdep_is_held           | 2          |
|           | include/linux/rcupdate.h                             | call_rcu_hurry            | 1          |
|           | include/linux/atomic/atomic-instrumented.h           | atomic_set                | 1          |
|           | include/linux/eventfd.h                              | eventfd_signal_allowed    | 1          |
|           | include/linux/rcupdate.h                             | rcu_read_unlock           | 2          |
|           | include/linux/rcupdate.h                             | rcu_dereference_protected | 2          |
|           | include/linux/rcupdate.h                             | rcu_read_lock             | 1          |
|           | io_uring/eventfd.c                                   | io_eventfd_put            | 3          |
|           | include/linux/rcupdate.h                             | call_rcu                  | 1          |
|           | include/linux/eventfd.h                              | eventfd_signal_mask       | 2          |
|           | io_uring/eventfd.c                                   | __io_eventfd_signal       | 2          |
|           | tools/testing/selftests/kvm/include/arm64/spinlock.h | spin_lock                 | 2          |
|           | include/linux/slab.h                                 | kmalloc                   | 1          |
|           | tools/testing/selftests/kvm/include/arm64/spinlock.h | spin_unlock               | 2          |
|           | include/linux/slab.h                                 | kfree                     | 2          |
|           | include/linux/refcount.h                             | refcount_dec_and_test     | 1          |
|           | include/linux/refcount.h                             | refcount_inc_not_zero     | 1          |
|           | io_uring/eventfd.c                                   | io_eventfd_grab           | 2          |


### fdinfo.c

| Source   | Library                          | Function Utilized           | Times Used |
| -------- | -------------------------------- | --------------------------- | ---------- |
| fdinfo.c | include/linux/spinlock.h         | spin_unlock                 | 1          |
|          | include/linux/seq_file.h         | seq_puts                    | 9          |
|          | include/linux/xarray.h           | xa_for_each                 | 1          |
|          | io_uring/fdinfo.c                | io_uring_show_cred          | 1          |
|          | include/linux/mutex.h            | mutex_trylock               | 1          |
|          | io_uring/fdinfo.c                | common_tracking_show_fdinfo | 2          |
|          | include/linux/comedi/comedidev.h | spin_lock                   | 1          |
|          | include/linux/seq_file.h         | seq_file_path               | 1          |
|          | io_uring/fdinfo.c                | napi_show_fdinfo            | 1          |
|          | include/linux/list.h             | hlist_for_each_entry        | 1          |
|          | include/linux/uidgid.h           | from_kuid_munged            | 4          |
|          | include/linux/resource.h         | getrusage                   | 1          |
|          | include/linux/seq_file.h         | seq_printf                  | 32         |
|          | include/linux/minmax.h           | min                         | 2          |
|          | include/asm-generic/rwonce.h     | READ_ONCE                   | 6          |
|          | include/linux/io_uring.h         | io_uring_get_opcode         | 1          |
|          | include/linux/seq_file.h         | seq_put_decimal_ull         | 9          |
|          | include/linux/uidgid.h           | from_kgid_munged            | 5          |
|          | include/linux/xarray.h           | xa_empty                    | 1          |
|          | include/linux/seq_file.h         | seq_put_hex_ll              | 1          |
|          | fs/seq_file.c                    | seq_putc                    | 1          |
|          | io_uring/filetable.h             | io_slot_file                | 1          |
|          | include/linux/task_work.h        | task_work_pending           | 1          |
|          | include/linux/seq_file.h         | seq_user_ns                 | 1          |
|          | include/linux/mutex.h            | mutex_unlock                | 1          |
|          | include/linux/list.h             | list_for_each_entry         | 1          |

### filetable.c

| Source      | Library                        | Function Utilized             | Times Used |
| ----------- | ------------------------------ | ----------------------------- | ---------- |
| filetable.c | io_uring/filetable.h           | io_fixed_file_set             | 1          |
|             | io_uring/io_uring.h            | io_ring_submit_unlock         | 1          |
|             | io_uring/rsrc.h                | io_rsrc_node_alloc            | 1          |
|             | fs/file_table.c                | fput                          | 1          |
|             | include/linux/io_uring.h       | io_is_uring_fops              | 1          |
|             | io_uring/filetable.c           | io_install_fixed_file         | 1          |
|             | include/linux/compiler.h       | unlikely                      | 3          |
|             | io_uring/filetable.c           | io_file_bitmap_get            | 1          |
|             | lib/bitmap.c                   | bitmap_zalloc                 | 1          |
|             | lib/bitmap.c                   | bitmap_free                   | 1          |
|             | io_uring/filetable.h           | io_file_bitmap_clear          | 1          |
|             | include/linux/compiler_types.h | __must_hold                   | 1          |
|             | io_uring/rsrc.h                | io_reset_rsrc_node            | 2          |
|             | include/linux/overflow.h       | check_add_overflow            | 1          |
|             | io_uring/filetable.h           | io_file_bitmap_set            | 1          |
|             | io_uring/rsrc.h                | io_rsrc_node_lookup           | 1          |
|             | io_uring/rsrc.h                | io_rsrc_data_free             | 2          |
|             | io_uring/filetable.h           | __io_fixed_fd_install         | 1          |
|             | io_uring/filetable.h           | io_file_table_set_alloc_range | 1          |
|             | include/linux/uaccess.h        | copy_from_user                | 1          |
|             | io_uring/rsrc.c                | io_rsrc_data_alloc            | 1          |
|             | io_uring/io_uring.h            | io_ring_submit_lock           | 1          |
|             | include/linux/find.h           | find_next_zero_bit            | 1          |

### fs.c

| Source | Library                        | Function Utilized | Times Used |
| ------ | ------------------------------ | ----------------- | ---------- |
| fs.c   | fs/namei.c                     | do_rmdir          | 1          |
|        | fs/namei.c                     | getname_uflags    | 1          |
|        | fs/namei.c                     | do_unlinkat       | 1          |
|        | include/linux/err.h            | IS_ERR            | 8          |
|        | fs/namei.c                     | do_renameat2      | 1          |
|        | include/linux/err.h            | PTR_ERR           | 8          |
|        | include/asm-generic/rwonce.h   | READ_ONCE         | 19         |
|        | fs/namei.c                     | do_symlinkat      | 1          |
|        | include/linux/kernel.h         | u64_to_user_ptr   | 8          |
|        | io_uring/io_uring.h            | io_req_set_res    | 5          |
|        | fs/namei.c                     | do_mkdirat        | 1          |
|        | include/linux/fs.h             | getname           | 7          |
|        | include/linux/compiler.h       | unlikely          | 5          |
|        | fs/namei.c                     | do_linkat         | 1          |
|        | fs/namei.c                     | putname           | 9          |
|        | include/asm-generic/bug.h      | WARN_ON_ONCE      | 5          |
|        | include/linux/io_uring_types.h | io_kiocb_to_cmd   | 14         |


### futex.c

| Source  | Library                                        | Function Utilized      | Times Used |
| ------- | ---------------------------------------------- | ---------------------- | ---------- |
| futex.c | io_uring/io_uring.c                            | io_req_task_complete   | 1          |
|         | io_uring/io_uring.h                            | io_tw_lock             | 2          |
|         | io_uring/alloc_cache.h                         | io_cache_free          | 1          |
|         | kernel/futex/futex.h                           | futex_flags_valid      | 1          |
|         | io_uring/alloc_cache.c                         | io_alloc_cache_free    | 1          |
|         | io_uring/alloc_cache.c                         | io_alloc_cache_init    | 1          |
|         | io_uring/alloc_cache.c                         | io_cache_alloc         | 1          |
|         | tools/virtio/ringtest/ptr_ring.c               | kcalloc                | 1          |
|         | include/linux/kernel.h                         | u64_to_user_ptr        | 2          |
|         | io_uring/cancel.c                              | io_cancel_remove       | 1          |
|         | include/linux/sched.h                          | __set_current_state    | 1          |
|         | include/linux/io_uring_types.h                 | io_kiocb_to_cmd        | 8          |
|         | io_uring/io_uring.h                            | io_req_set_res         | 8          |
|         | io_uring/io_uring.h                            | io_req_task_work_add   | 3          |
|         | include/linux/list.h                           | hlist_del_init         | 2          |
|         | include/linux/bitops.h                         | test_bit               | 1          |
|         | io_uring/futex.c                               | io_futexv_claim        | 2          |
|         | kernel/futex/futex.h                           | futex_validate_input   | 2          |
|         | include/linux/slab.h                           | kfree                  | 4          |
|         | include/asm-generic/bitops/instrumented-lock.h | test_and_set_bit_lock  | 1          |
|         | include/linux/compiler.h                       | unlikely               | 5          |
|         | include/linux/compiler.h                       | io_cancel_remove_all   | 1          |
|         | io_uring/cancel.h                              | futex2_to_flags        | 1          |
|         | include/linux/list.h                           | hlist_add_head         | 2          |
|         | kernel/futex/waitwake.c                        | futex_wait_setup       | 1          |
|         | kernel/futex/core.c                            | futex_unqueue          | 1          |
|         | kernel/futex/futex.h                           | futex_queue            | 1          |
|         | io_uring/io_uring.h                            | io_ring_submit_lock    | 2          |
|         | kernel/futex/waitwake.c                        | futex_unqueue_multiple | 1          |

### io_uring.c
| Source     | Library/Header                                            | Function                                  | Times Used |
| ---------- | --------------------------------------------------------- | ----------------------------------------- | ---------- |
| io_uring.c | arch/parisc/kernel/firmware.c                             | __acquires                                | 1          |
|            | include/linux/linkage.h                                   | ALIGN                                     | 1          |
|            | kernel/workqueue.c                                        | alloc_workqueue                           | 1          |
|            | fs/anon_inodes.c                                          | anon_inode_create_getfile                 | 1          |
|            | include/linux/nospec.h                                    | array_index_nospec                        | 4          |
|            | drivers/gpu/drm/imagination/pvr_stream.h                  | array_size                                | 3          |
|            | arch/mips/boot/tools/relocs.h                             | ARRAY_SIZE                                | 2          |
|            | include/linux/atomic/atomic-instrumented.h                | atomic_andnot                             | 3          |
|            | include/linux/atomic/atomic-instrumented.h                | atomic_dec                                | 2          |
|            | include/linux/atomic/atomic-instrumented.h                | atomic_inc                                | 2          |
|            | include/linux/atomic/atomic-instrumented.h                | atomic_or                                 | 8          |
|            | include/linux/atomic/atomic-instrumented.h                | atomic_read                               | 7          |
|            | include/linux/atomic/atomic-instrumented.h                | atomic_set                                | 6          |
|            | include/linux/audit.h                                     | audit_uring_entry                         | 1          |
|            | include/linux/audit.h                                     | audit_uring_exit                          | 1          |
|            | kernel/sched/wait.c                                       | autoremove_wake_function                  | 1          |
|            | drivers/comedi/drivers/ni_routing/tools/convert_c_to_py.c | BIT                                       | 5          |
|            | block/blk-core.c                                          | blk_finish_plug                           | 1          |
|            | block/blk-core.c                                          | blk_start_plug_nr_ios                     | 1          |
|            | arch/mips/include/asm/bug.h                               | BUG_ON                                    | 2          |
|            | arch/x86/include/asm/kvm-x86-ops.h                        | BUILD_BUG_ON                              | 16         |
|            | io_uring/io_uring.c                                       | BUILD_BUG_SQE_ELEM                        | 43         |
|            | io_uring/io_uring.c                                       | BUILD_BUG_SQE_ELEM_SIZE                   | 1          |
|            | io_uring/io_uring.c                                       | __BUILD_BUG_VERIFY_OFFSET_SIZE            | 2          |
|            | arch/powerpc/kernel/iommu.c                               | capable                                   | 1          |
|            | include/linux/overflow.h                                  | check_add_overflow                        | 2          |
|            | include/linux/overflow.h                                  | check_shl_overflow                        | 1          |
|            | drivers/media/platform/ti/omap3isp/ispccdc.h              | clamp                                     | 1          |
|            | arch/alpha/include/asm/agp_backend.h                      | cleanup                                   | 1          |
|            | arch/alpha/include/asm/bitops.h                           | clear_bit                                 | 2          |
|            | arch/arm/mach-rpc/ecard.c                                 | complete                                  | 2          |
|            | include/linux/sched.h                                     | cond_resched                              | 8          |
|            | drivers/gpu/drm/radeon/mkregtable.c                       | container_of                              | 20         |
|            | include/linux/uaccess.h                                   | copy_from_user                            | 3          |
|            | include/linux/uaccess.h                                   | copy_to_user                              | 1          |
|            | io_uring/io_uring.c                                       | ctx_flush_and_put                         | 3          |
|            | include/linux/cred.h                                      | current_cred                              | 1          |
|            | io_uring/io_uring.c                                       | current_pending_io                        | 1          |
|            | include/linux/cred.h                                      | current_user                              | 1          |
|            | include/linux/wait.h                                      | DEFINE_WAIT                               | 1          |
|            | include/linux/hrtimer.h                                   | destroy_hrtimer_on_stack                  | 1          |
|            | include/linux/err.h                                       | ERR_PTR                                   | 2          |
|            | arch/arm/vdso/vdsomunge.c                                 | fail                                      | 1          |
|            | fs/file.c                                                 | fd_install                                | 1          |
|            | arch/alpha/kernel/osf_sys.c                               | fget                                      | 2          |
|            | include/linux/fs.h                                        | file_inode                                | 3          |
|            | kernel/sched/wait.c                                       | finish_wait                               | 2          |
|            | kernel/workqueue.c                                        | flush_delayed_work                        | 4          |
|            | fs/file_table.c                                           | fput                                      | 2          |
|            | kernel/user.c                                             | free_uid                                  | 1          |
|            | arch/mips/include/asm/mips-r2-to-r6-emul.h                | func                                      | 1          |
|            | include/linux/cred.h                                      | get_cred                                  | 1          |
|            | include/linux/cred.h                                      | get_current_cred                          | 1          |
|            | include/linux/sched/task.h                                | get_task_struct                           | 1          |
|            | kernel/time/time.c                                        | get_timespec64                            | 1          |
|            | drivers/s390/block/dasd_eckd.c                            | get_uid                                   | 1          |
|            | fs/file.c                                                 | get_unused_fd_flags                       | 1          |
|            | include/linux/uidgid.h                                    | gid_valid                                 | 1          |
|            | drivers/gpu/drm/i915/i915_vma_resource.h                  | guard                                     | 1          |
|            | kernel/time/hrtimer.c                                     | hrtimer_cancel                            | 1          |
|            | include/linux/hrtimer.h                                   | hrtimer_set_expires                       | 1          |
|            | include/linux/hrtimer.h                                   | hrtimer_set_expires_range_ns              | 1          |
|            | kernel/time/hrtimer.c                                     | hrtimer_setup_on_stack                    | 2          |
|            | include/linux/hrtimer.h                                   | hrtimer_start_expires                     | 1          |
|            | include/linux/hrtimer.h                                   | hrtimer_update_function                   | 1          |
|            | include/linux/log2.h                                      | ilog2                                     | 1          |
|            | arch/sparc/include/asm/compat.h                           | in_compat_syscall                         | 2          |
|            | include/linux/indirect_call_wrapper.h                     | INDIRECT_CALL_2                           | 2          |
|            | include/linux/cred.h                                      | in_group_p                                | 1          |
|            | drivers/bluetooth/hci_nokia.c                             | init_completion                           | 2          |
|            | include/linux/workqueue.h                                 | INIT_DELAYED_WORK                         | 1          |
|            | include/linux/list.h                                      | INIT_HLIST_HEAD                           | 4          |
|            | drivers/gpu/drm/radeon/mkregtable.c                       | INIT_LIST_HEAD                            | 7          |
|            | include/linux/llist.h                                     | init_llist_head                           | 1          |
|            | include/linux/task_work.h                                 | init_task_work                            | 2          |
|            | include/linux/wait.h                                      | init_waitqueue_func_entry                 | 1          |
|            | include/linux/wait.h                                      | init_waitqueue_head                       | 3          |
|            | include/linux/workqueue.h                                 | INIT_WORK                                 | 1          |
|            | io_uring/slist.h                                          | INIT_WQ_LIST                              | 3          |
|            | io_uring/io_uring.c                                       | io_account_cq_overflow                    | 1          |
|            | io_uring/io_uring.c                                       | io_activate_pollwq                        | 1          |
|            | io_uring/io_uring.c                                       | io_allocate_scq_urings                    | 1          |
|            | io_uring/alloc_cache.c                                    | io_alloc_cache_free                       | 5          |
|            | io_uring/alloc_cache.c                                    | io_alloc_cache_init                       | 5          |
|            | io_uring/io_uring.c                                       | io_alloc_hash_table                       | 1          |
|            | io_uring/io_uring.h                                       | io_alloc_req                              | 1          |
|            | io_uring/io_uring.h                                       | io_allowed_defer_tw_run                   | 1          |
|            | io_uring/io_uring.h                                       | io_allowed_run_tw                         | 2          |
|            | io_uring/io_uring.c                                       | __io_arm_ltimeout                         | 1          |
|            | io_uring/io_uring.c                                       | io_arm_ltimeout                           | 2          |
|            | io_uring/poll.c                                           | io_arm_poll_handler                       | 3          |
|            | io_uring/io_uring.c                                       | io_assign_file                            | 2          |
|            | io_uring/alloc_cache.h                                    | io_cache_free                             | 1          |
|            | io_uring/io_uring.c                                       | io_cancel_defer_files                     | 1          |
|            | io_uring/io_uring.c                                       | io_check_restriction                      | 1          |
|            | io_uring/io_uring.c                                       | io_clean_op                               | 1          |
|            | io_uring/io_uring.h                                       | io_commit_cqring                          | 2          |
|            | io_uring/io_uring.h                                       | io_commit_cqring_flush                    | 2          |
|            | io_uring/io_uring.c                                       | io_commit_sqring                          | 1          |
|            | io_uring/io_uring.c                                       | __io_cq_lock                              | 2          |
|            | io_uring/io_uring.c                                       | io_cq_lock                                | 4          |
|            | io_uring/io_uring.c                                       | io_cqring_do_overflow_flush               | 2          |
|            | io_uring/io_uring.c                                       | io_cqring_event_overflow                  | 3          |
|            | io_uring/io_uring.c                                       | __io_cqring_events                        | 3          |
|            | io_uring/io_uring.c                                       | io_cqring_events                          | 2          |
|            | io_uring/io_uring.c                                       | __io_cqring_events_user                   | 2          |
|            | io_uring/io_uring.c                                       | __io_cqring_overflow_flush                | 3          |
|            | io_uring/io_uring.c                                       | io_cqring_overflow_kill                   | 2          |
|            | io_uring/io_uring.c                                       | io_cqring_schedule_timeout                | 1          |
|            | io_uring/io_uring.c                                       | io_cqring_timer_wakeup                    | 1          |
|            | io_uring/io_uring.c                                       | io_cqring_wait                            | 1          |
|            | io_uring/io_uring.c                                       | __io_cqring_wait_schedule                 | 1          |
|            | io_uring/io_uring.c                                       | io_cqring_wait_schedule                   | 1          |
|            | io_uring/io_uring.h                                       | io_cqring_wake                            | 2          |
|            | io_uring/io_uring.c                                       | __io_cq_unlock_post                       | 2          |
|            | io_uring/io_uring.c                                       | io_cq_unlock_post                         | 4          |
|            | io_uring/memmap.c                                         | io_create_region                          | 2          |
|            | io_uring/kbuf.c                                           | io_destroy_buffers                        | 1          |
|            | io_uring/timeout.c                                        | io_disarm_next                            | 1          |
|            | io_uring/rw.c                                             | io_do_iopoll                              | 2          |
|            | io_uring/io_uring.c                                       | io_drain_req                              | 1          |
|            | io_uring/eventfd.c                                        | io_eventfd_flush_signal                   | 1          |
|            | io_uring/eventfd.c                                        | io_eventfd_signal                         | 1          |
|            | io_uring/eventfd.c                                        | io_eventfd_unregister                     | 1          |
|            | io_uring/io_uring.h                                       | io_extract_req                            | 1          |
|            | io_uring/io_uring.c                                       | __io_fallback_tw                          | 3          |
|            | io_uring/io_uring.c                                       | io_fallback_tw                            | 2          |
|            | io_uring/io_uring.h                                       | io_file_can_poll                          | 2          |
|            | io_uring/io_uring.c                                       | io_file_get_fixed                         | 1          |
|            | io_uring/io_uring.c                                       | io_file_get_flags                         | 1          |
|            | io_uring/io_uring.c                                       | io_file_get_normal                        | 1          |
|            | io_uring/io_uring.c                                       | io_fill_cqe_aux                           | 3          |
|            | io_uring/io_uring.h                                       | io_fill_cqe_req                           | 2          |
|            | io_uring/timeout.c                                        | io_flush_timeouts                         | 1          |
|            | io_uring/io_uring.h                                       | io_for_each_link                          | 4          |
|            | io_uring/io_uring.c                                       | io_free_alloc_caches                      | 2          |
|            | io_uring/io_uring.c                                       | io_free_batch_list                        | 1          |
|            | io_uring/memmap.c                                         | io_free_region                            | 3          |
|            | io_uring/io_uring.c                                       | io_free_req                               | 1          |
|            | io_uring/futex.c                                          | io_futex_cache_free                       | 1          |
|            | io_uring/futex.c                                          | io_futex_cache_init                       | 1          |
|            | io_uring/futex.c                                          | io_futex_remove_all                       | 1          |
|            | io_uring/io_uring.h                                       | io_get_cqe                                | 1          |
|            | io_uring/io_uring.h                                       | io_get_cqe_overflow                       | 1          |
|            | io_uring/io_uring.c                                       | io_get_ext_arg                            | 1          |
|            | io_uring/io_uring.c                                       | io_get_ext_arg_reg                        | 1          |
|            | io_uring/io_uring.c                                       | io_get_sequence                           | 1          |
|            | io_uring/io_uring.c                                       | io_get_sqe                                | 1          |
|            | io_uring/io_uring.h                                       | io_get_task_refs                          | 1          |
|            | io_uring/io_uring.h                                       | io_get_time                               | 1          |
|            | io_uring/io_uring.c                                       | io_handle_tw_list                         | 1          |
|            | io_uring/io_uring.h                                       | io_has_work                               | 3          |
|            | io_uring/io_uring.c                                       | io_init_drain                             | 1          |
|            | io_uring/io_uring.c                                       | io_init_fail_req                          | 9          |
|            | io_uring/io_uring.c                                       | io_init_req                               | 1          |
|            | io_uring/io_uring.c                                       | io_iopoll_check                           | 1          |
|            | io_uring/io_uring.c                                       | io_iopoll_req_issued                      | 1          |
|            | io_uring/io_uring.c                                       | io_iopoll_try_reap_events                 | 1          |
|            | io_uring/io_uring.c                                       | __io_issue_sqe                            | 2          |
|            | io_uring/io_uring.c                                       | io_issue_sqe                              | 2          |
|            | include/linux/io_uring.h                                  | io_is_uring_fops                          | 2          |
|            | io_uring/kbuf.c                                           | io_kbuf_drop_legacy                       | 1          |
|            | io_uring/kbuf.h                                           | io_kbuf_recycle                           | 2          |
|            | io_uring/timeout.c                                        | io_kill_timeouts                          | 1          |
|            | io_uring/io_uring.h                                       | io_local_work_pending                     | 7          |
|            | io_uring/io_uring.c                                       | io_match_linked                           | 2          |
|            | io_uring/io_uring.c                                       | io_match_task_safe                        | 2          |
|            | io_uring/io_uring.c                                       | io_move_task_work_from_local              | 1          |
|            | io_uring/napi.h                                           | io_napi_busy_loop                         | 1          |
|            | io_uring/napi.c                                           | io_napi_free                              | 1          |
|            | io_uring/napi.c                                           | io_napi_init                              | 1          |
|            | io_uring/poll.c                                           | io_poll_remove_all                        | 1          |
|            | io_uring/io_uring.h                                       | io_poll_wq_wake                           | 1          |
|            | io_uring/io_uring.c                                       | io_preinit_req                            | 1          |
|            | io_uring/io_uring.c                                       | io_prep_async_link                        | 2          |
|            | io_uring/io_uring.c                                       | io_prep_async_work                        | 2          |
|            | io_uring/io_uring.c                                       | __io_prep_linked_timeout                  | 2          |
|            | io_uring/io_uring.c                                       | io_prep_linked_timeout                    | 2          |
|            | io_uring/io_uring.h                                       | io_put_file                               | 1          |
|            | io_uring/kbuf.h                                           | io_put_kbuf                               | 1          |
|            | io_uring/io_uring.c                                       | io_put_task                               | 1          |
|            | io_uring/io_uring.c                                       | io_queue_async                            | 1          |
|            | io_uring/io_uring.c                                       | io_queue_deferred                         | 1          |
|            | io_uring/io_uring.c                                       | io_queue_iowq                             | 5          |
|            | io_uring/timeout.c                                        | io_queue_linked_timeout                   | 3          |
|            | io_uring/io_uring.c                                       | io_queue_next                             | 1          |
|            | io_uring/io_uring.c                                       | io_queue_sqe                              | 2          |
|            | io_uring/io_uring.c                                       | io_queue_sqe_fallback                     | 3          |
|            | io_uring/memmap.h                                         | io_region_get_ptr                         | 2          |
|            | io_uring/io_uring.c                                       | io_req_add_to_cache                       | 3          |
|            | io_uring/rsrc.h                                           | io_req_assign_rsrc_node                   | 1          |
|            | io_uring/io_uring.h                                       | io_req_cache_empty                        | 2          |
|            | io_uring/io_uring.c                                       | io_req_caches_free                        | 2          |
|            | io_uring/io_uring.h                                       | io_req_complete_defer                     | 3          |
|            | io_uring/io_uring.c                                       | io_req_complete_post                      | 1          |
|            | io_uring/io_uring.c                                       | io_req_cqe_overflow                       | 2          |
|            | io_uring/io_uring.c                                       | io_req_defer_failed                       | 5          |
|            | io_uring/io_uring.c                                       | io_req_find_next                          | 2          |
|            | io_uring/io_uring.c                                       | __io_req_find_next_prep                   | 1          |
|            | io_uring/io_uring.c                                       | io_req_local_work_add                     | 1          |
|            | io_uring/io_uring.c                                       | io_req_normal_work_add                    | 1          |
|            | io_uring/rsrc.h                                           | io_req_put_rsrc_nodes                     | 1          |
|            | io_uring/refs.h                                           | __io_req_set_refcount                     | 2          |
|            | io_uring/refs.h                                           | io_req_set_refcount                       | 1          |
|            | io_uring/io_uring.h                                       | io_req_set_res                            | 3          |
|            | io_uring/io_uring.c                                       | io_req_task_queue                         | 4          |
|            | io_uring/io_uring.c                                       | io_req_task_queue_fail                    | 4          |
|            | io_uring/io_uring.c                                       | __io_req_task_work_add                    | 1          |
|            | io_uring/io_uring.h                                       | io_req_task_work_add                      | 5          |
|            | io_uring/io_uring.c                                       | io_req_track_inflight                     | 1          |
|            | io_uring/tctx.c                                           | io_ring_add_registered_file               | 1          |
|            | io_uring/io_uring.c                                       | io_ring_ctx_alloc                         | 1          |
|            | io_uring/io_uring.c                                       | io_ring_ctx_free                          | 1          |
|            | io_uring/io_uring.c                                       | io_ring_ctx_wait_and_kill                 | 2          |
|            | io_uring/io_uring.c                                       | io_rings_free                             | 3          |
|            | io_uring/io_uring.h                                       | io_ring_submit_lock                       | 1          |
|            | io_uring/io_uring.h                                       | io_ring_submit_unlock                     | 1          |
|            | io_uring/rsrc.c                                           | io_rsrc_cache_free                        | 1          |
|            | io_uring/rsrc.c                                           | io_rsrc_cache_init                        | 1          |
|            | io_uring/rsrc.h                                           | io_rsrc_node_lookup                       | 1          |
|            | io_uring/io_uring.c                                       | __io_run_local_work                       | 2          |
|            | io_uring/io_uring.c                                       | io_run_local_work                         | 4          |
|            | io_uring/io_uring.c                                       | io_run_local_work_continue                | 2          |
|            | io_uring/io_uring.c                                       | io_run_local_work_locked                  | 2          |
|            | io_uring/io_uring.c                                       | __io_run_local_work_loop                  | 2          |
|            | io_uring/io_uring.h                                       | io_run_task_work                          | 6          |
|            | io_uring/io_uring.h                                       | io_should_terminate_tw                    | 1          |
|            | io_uring/io_uring.h                                       | io_should_wake                            | 3          |
|            | io_uring/zcrx.c                                           | io_shutdown_zcrx_ifqs                     | 1          |
|            | io_uring/filetable.h                                      | io_slot_file                              | 1          |
|            | io_uring/filetable.h                                      | io_slot_flags                             | 1          |
|            | io_uring/rsrc.c                                           | io_sqe_buffers_unregister                 | 1          |
|            | io_uring/rsrc.c                                           | io_sqe_files_unregister                   | 1          |
|            | io_uring/sqpoll.c                                         | io_sq_offload_create                      | 1          |
|            | io_uring/sqpoll.c                                         | io_sqpoll_wait_sq                         | 1          |
|            | io_uring/io_uring.h                                       | io_sqring_entries                         | 1          |
|            | io_uring/io_uring.h                                       | io_sqring_full                            | 1          |
|            | io_uring/sqpoll.c                                         | io_sq_thread_finish                       | 1          |
|            | io_uring/sqpoll.c                                         | io_sq_thread_park                         | 1          |
|            | io_uring/sqpoll.c                                         | io_sq_thread_unpark                       | 1          |
|            | io_uring/io_uring.c                                       | io_submit_fail_init                       | 1          |
|            | io_uring/io_uring.h                                       | io_submit_flush_completions               | 4          |
|            | io_uring/io_uring.c                                       | io_submit_sqe                             | 1          |
|            | io_uring/io_uring.c                                       | io_submit_sqes                            | 1          |
|            | io_uring/io_uring.c                                       | io_submit_state_end                       | 1          |
|            | io_uring/io_uring.c                                       | io_submit_state_start                     | 1          |
|            | io_uring/io_uring.h                                       | io_task_work_pending                      | 1          |
|            | io_uring/io_uring.h                                       | io_tw_lock                                | 3          |
|            | io_uring/register.c                                       | io_unregister_personality                 | 1          |
|            | io_uring/zcrx.c                                           | io_unregister_zcrx_ifqs                   | 1          |
|            | io_uring/tctx.c                                           | __io_uring_add_tctx_node                  | 1          |
|            | io_uring/tctx.h                                           | io_uring_add_tctx_node                    | 1          |
|            | io_uring/io_uring.c                                       | io_uring_allowed                          | 1          |
|            | io_uring/io_uring.c                                       | io_uring_cancel_generic                   | 1          |
|            | io_uring/tctx.c                                           | io_uring_clean_tctx                       | 1          |
|            | io_uring/io_uring.c                                       | io_uring_create                           | 1          |
|            | io_uring/tctx.c                                           | io_uring_del_tctx_node                    | 1          |
|            | io_uring/io_uring.c                                       | io_uring_drop_tctx_refs                   | 3          |
|            | io_uring/io_uring.c                                       | io_uring_fill_params                      | 1          |
|            | io_uring/tctx.c                                           | __io_uring_free                           | 1          |
|            | io_uring/io_uring.c                                       | io_uring_get_file                         | 1          |
|            | io_uring/io_uring.c                                       | io_uring_install_fd                       | 1          |
|            | io_uring/opdef.c                                          | io_uring_optable_init                     | 1          |
|            | io_uring/io_uring.c                                       | io_uring_sanitise_params                  | 1          |
|            | io_uring/io_uring.c                                       | io_uring_setup                            | 1          |
|            | io_uring/io_uring.c                                       | io_uring_try_cancel_iowq                  | 1          |
|            | io_uring/io_uring.c                                       | io_uring_try_cancel_requests              | 3          |
|            | io_uring/uring_cmd.c                                      | io_uring_try_cancel_uring_cmd             | 1          |
|            | io_uring/tctx.c                                           | io_uring_unreg_ringfd                     | 1          |
|            | io_uring/io_uring.c                                       | io_validate_ext_arg                       | 1          |
|            | io_uring/waitid.c                                         | io_waitid_remove_all                      | 1          |
|            | io_uring/io-wq.c                                          | io_wq_cancel_cb                           | 3          |
|            | io_uring/io-wq.h                                          | io_wq_current_is_worker                   | 1          |
|            | io_uring/io-wq.c                                          | io_wq_enqueue                             | 1          |
|            | io_uring/io-wq.c                                          | io_wq_exit_start                          | 1          |
|            | io_uring/io-wq.c                                          | io_wq_hash_work                           | 1          |
|            | io_uring/io-wq.h                                          | io_wq_is_hashed                           | 1          |
|            | io_uring/io-wq.h                                          | io_wq_put_hash                            | 1          |
|            | io_uring/io-wq.c                                          | io_wq_worker_stopped                      | 1          |
|            | crypto/asymmetric_keys/x509_parser.h                      | IS_ERR                                    | 2          |
|            | block/blk-rq-qos.h                                        | issue                                     | 1          |
|            | include/linux/slab.h                                      | kfree                                     | 10         |
|            | include/linux/slab.h                                      | kmalloc                                   | 2          |
|            | include/linux/slab.h                                      | kmem_cache_alloc                          | 1          |
|            | include/linux/slab.h                                      | kmem_cache_alloc_bulk                     | 1          |
|            | include/linux/slab.h                                      | kmem_cache_create                         | 1          |
|            | mm/slub.c                                                 | kmem_cache_free                           | 1          |
|            | include/linux/ktime.h                                     | ktime_add                                 | 1          |
|            | include/linux/ktime.h                                     | ktime_add_ns                              | 1          |
|            | include/linux/ktime.h                                     | ktime_compare                             | 1          |
|            | drivers/vdpa/mlx5/core/mr.c                               | kvfree                                    | 2          |
|            | include/linux/slab.h                                      | kvmalloc_array                            | 1          |
|            | include/linux/slab.h                                      | kzalloc                                   | 1          |
|            | include/linux/compiler.h                                  | likely                                    | 6          |
|            | drivers/gpu/drm/radeon/mkregtable.c                       | list_add_tail                             | 2          |
|            | include/linux/list.h                                      | list_cut_position                         | 1          |
|            | include/linux/list.h                                      | list_del                                  | 1          |
|            | include/linux/list.h                                      | list_del_init                             | 2          |
|            | drivers/net/wireless/ath/ath11k/hal.h                     | list_empty                                | 9          |
|            | include/linux/list.h                                      | list_empty_careful                        | 1          |
|            | include/linux/list.h                                      | list_first_entry                          | 4          |
|            | drivers/gpu/drm/radeon/mkregtable.c                       | list_for_each_entry                       | 2          |
|            | include/linux/list.h                                      | list_for_each_entry_reverse               | 1          |
|            | include/linux/list.h                                      | LIST_HEAD                                 | 1          |
|            | include/linux/list.h                                      | list_rotate_left                          | 1          |
|            | include/linux/llist.h                                     | llist_add                                 | 2          |
|            | include/linux/llist.h                                     | llist_del_all                             | 6          |
|            | include/linux/llist.h                                     | llist_empty                               | 1          |
|            | include/linux/llist.h                                     | llist_for_each_entry_safe                 | 1          |
|            | lib/llist.c                                               | llist_reverse_order                       | 2          |
|            | include/linux/lockdep.h                                   | lockdep_assert                            | 1          |
|            | include/linux/lockdep.h                                   | lockdep_assert_held                       | 5          |
|            | include/linux/uidgid.h                                    | make_kgid                                 | 1          |
|            | Documentation/scheduler/sched-pelt.c                      | max                                       | 2          |
|            | arch/alpha/include/asm/string.h                           | memcpy                                    | 1          |
|            | arch/alpha/include/asm/string.h                           | memset                                    | 6          |
|            | arch/arc/include/asm/arcregs.h                            | min                                       | 4          |
|            | arch/powerpc/boot/types.h                                 | min_t                                     | 1          |
|            | include/linux/sched/mm.h                                  | mmdrop                                    | 1          |
|            | include/linux/sched/mm.h                                  | mmgrab                                    | 1          |
|            | drivers/block/aoe/aoenet.c                                | __must_hold                               | 11         |
|            | include/linux/mutex.h                                     | mutex_init                                | 2          |
|            | include/linux/mutex.h                                     | mutex_lock                                | 21         |
|            | include/linux/mutex.h                                     | mutex_unlock                              | 22         |
|            | arch/arm64/include/asm/thread_info.h                      | need_resched                              | 4          |
|            | include/linux/capability.h                                | ns_capable_noaudit                        | 1          |
|            | drivers/gpu/drm/radeon/mkregtable.c                       | offsetof                                  | 21         |
|            | include/linux/cred.h                                      | override_creds                            | 1          |
|            | arch/powerpc/boot/page.h                                  | PAGE_ALIGN                                | 2          |
|            | include/linux/percpu_counter.h                            | percpu_counter_add                        | 1          |
|            | include/linux/percpu_counter.h                            | percpu_counter_read_positive              | 1          |
|            | include/linux/percpu_counter.h                            | percpu_counter_sub                        | 2          |
|            | include/linux/percpu_counter.h                            | percpu_counter_sum                        | 1          |
|            | lib/percpu-refcount.c                                     | percpu_ref_exit                           | 2          |
|            | include/linux/percpu-refcount.h                           | percpu_ref_get                            | 4          |
|            | include/linux/percpu-refcount.h                           | percpu_ref_get_many                       | 1          |
|            | lib/percpu-refcount.c                                     | percpu_ref_init                           | 1          |
|            | include/linux/percpu-refcount.h                           | percpu_ref_kill                           | 1          |
|            | include/linux/percpu-refcount.h                           | percpu_ref_put                            | 6          |
|            | include/linux/percpu-refcount.h                           | percpu_ref_put_many                       | 1          |
|            | drivers/gpu/drm/i915/i915_perf.c                          | poll_wait                                 | 1          |
|            | include/keys/asymmetric-parser.h                          | prep                                      | 1          |
|            | kernel/sched/wait.c                                       | prepare_to_wait                           | 1          |
|            | kernel/sched/wait.c                                       | prepare_to_wait_exclusive                 | 1          |
|            | include/linux/err.h                                       | PTR_ERR                                   | 2          |
|            | include/linux/cred.h                                      | put_cred                                  | 3          |
|            | include/linux/sched/task.h                                | put_task_struct                           | 2          |
|            | include/linux/sched/task.h                                | put_task_struct_many                      | 1          |
|            | drivers/scsi/bfa/bfad_im.h                                | queue_work                                | 1          |
|            | include/linux/spinlock.h                                  | raw_spin_lock_init                        | 1          |
|            | include/linux/spinlock.h                                  | raw_spin_lock_irq                         | 2          |
|            | include/linux/spinlock.h                                  | raw_spin_unlock_irq                       | 2          |
|            | include/asm-generic/rwonce.h                              | READ_ONCE                                 | 31         |
|            | include/linux/refcount.h                                  | refcount_add                              | 1          |
|            | include/linux/sysctl.h                                    | register_sysctl_init                      | 1          |
|            | arch/parisc/kernel/firmware.c                             | __releases                                | 1          |
|            | io_uring/io_uring.c                                       | req_fail_link_node                        | 2          |
|            | io_uring/io_uring.c                                       | req_need_defer                            | 3          |
|            | io_uring/refs.h                                           | req_ref_get                               | 1          |
|            | io_uring/refs.h                                           | req_ref_put                               | 1          |
|            | block/blk.h                                               | req_ref_put_and_test                      | 1          |
|            | io_uring/refs.h                                           | req_ref_put_and_test_atomic               | 1          |
|            | io_uring/io_uring.h                                       | req_set_fail                              | 2          |
|            | include/linux/sched/signal.h                              | restore_saved_sigmask_unless              | 1          |
|            | include/linux/cred.h                                      | revert_creds                              | 1          |
|            | io_uring/io_uring.c                                       | rings_size                                | 1          |
|            | include/linux/log2.h                                      | roundup_pow_of_two                        | 2          |
|            | include/linux/sched/signal.h                              | same_thread_group                         | 1          |
|            | drivers/firmware/efi/libstub/efistub.h                    | schedule                                  | 3          |
|            | include/linux/workqueue.h                                 | schedule_delayed_work                     | 1          |
|            | include/linux/security.h                                  | security_uring_allowed                    | 1          |
|            | include/linux/security.h                                  | security_uring_override_creds             | 1          |
|            | arch/alpha/include/asm/bitops.h                           | set_bit                                   | 2          |
|            | kernel/signal.c                                           | set_compat_user_sigmask                   | 1          |
|            | include/linux/sched.h                                     | __set_current_state                       | 3          |
|            | include/linux/sched.h                                     | set_current_state                         | 1          |
|            | include/linux/sched/signal.h                              | __set_notify_signal                       | 1          |
|            | kernel/signal.c                                           | set_user_sigmask                          | 1          |
|            | include/uapi/linux/stat.h                                 | S_ISBLK                                   | 1          |
|            | include/uapi/linux/stat.h                                 | S_ISREG                                   | 1          |
|            | include/linux/stddef.h                                    | sizeof_field                              | 3          |
|            | arch/arm64/include/asm/vdso/compat_barrier.h              | smp_mb                                    | 2          |
|            | arch/arm64/include/asm/vdso/compat_barrier.h              | smp_rmb                                   | 1          |
|            | include/asm-generic/barrier.h                             | smp_store_release                         | 1          |
|            | drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.h                  | spin_lock                                 | 12         |
|            | include/linux/spinlock.h                                  | spin_lock_init                            | 2          |
|            | include/linux/spinlock.h                                  | spin_unlock                               | 14         |
|            | include/linux/jump_label.h                                | static_branch_dec                         | 1          |
|            | include/linux/jump_label.h                                | static_branch_inc                         | 1          |
|            | include/linux/jump_label.h                                | static_branch_unlikely                    | 1          |
|            | drivers/gpu/drm/amd/display/include/vector.h              | struct_size                               | 1          |
|            | kernel/rcu/tiny.c                                         | synchronize_rcu                           | 1          |
|            | include/linux/sched/signal.h                              | task_sigpending                           | 3          |
|            | kernel/task_work.c                                        | task_work_add                             | 3          |
|            | include/linux/task_work.h                                 | task_work_pending                         | 2          |
|            | io_uring/io_uring.c                                       | tctx_inflight                             | 3          |
|            | io_uring/io_uring.c                                       | tctx_task_work_run                        | 1          |
|            | arch/x86/boot/bitops.h                                    | test_bit                                  | 3          |
|            | include/linux/jiffies.h                                   | time_after                                | 2          |
|            | include/linux/ktime.h                                     | timespec64_to_ktime                       | 1          |
|            | unknown                                                   | trace_io_uring_complete                   | 1          |
|            | unknown                                                   | trace_io_uring_cqe_overflow               | 1          |
|            | unknown                                                   | trace_io_uring_cqring_wait                | 1          |
|            | unknown                                                   | trace_io_uring_create                     | 1          |
|            | unknown                                                   | trace_io_uring_defer                      | 1          |
|            | unknown                                                   | trace_io_uring_file_get                   | 1          |
|            | unknown                                                   | trace_io_uring_link                       | 1          |
|            | unknown                                                   | trace_io_uring_local_work_run             | 1          |
|            | unknown                                                   | trace_io_uring_queue_async_work           | 1          |
|            | unknown                                                   | trace_io_uring_req_failed                 | 1          |
|            | unknown                                                   | trace_io_uring_submit_req                 | 1          |
|            | unknown                                                   | trace_io_uring_task_work_run              | 1          |
|            | include/linux/atomic/atomic-instrumented.h                | try_cmpxchg                               | 1          |
|            | include/linux/kernel.h                                    | u64_to_user_ptr                           | 3          |
|            | include/linux/compiler.h                                  | unlikely                                  | 56         |
|            | arch/arm64/include/asm/uaccess.h                          | unsafe_get_user                           | 4          |
|            | arch/arm64/include/asm/uaccess.h                          | user_access_begin                         | 1          |
|            | arch/arm64/include/asm/uaccess.h                          | user_access_end                           | 2          |
|            | kernel/sched/completion.c                                 | wait_for_completion_interruptible         | 1          |
|            | kernel/sched/completion.c                                 | wait_for_completion_interruptible_timeout | 1          |
|            | include/linux/wait.h                                      | wake_up                                   | 3          |
|            | include/linux/wait.h                                      | wake_up_all                               | 1          |
|            | kernel/sched/core.c                                       | wake_up_process                           | 1          |
|            | kernel/sched/core.c                                       | wake_up_state                             | 1          |
|            | include/asm-generic/bug.h                                 | WARN_ON_ONCE                              | 16         |
|            | include/linux/wait.h                                      | wq_has_sleeper                            | 1          |
|            | io_uring/slist.h                                          | wq_list_add_head                          | 1          |
|            | io_uring/slist.h                                          | wq_list_add_tail                          | 1          |
|            | io_uring/slist.h                                          | wq_list_empty                             | 7          |
|            | io_uring/slist.h                                          | __wq_list_for_each                        | 1          |
|            | io_uring/slist.h                                          | wq_stack_add_head                         | 1          |
|            | include/asm-generic/rwonce.h                              | WRITE_ONCE                                | 9          |
|            | lib/xarray.c                                              | xa_destroy                                | 2          |
|            | include/linux/xarray.h                                    | xa_for_each                               | 3          |
|            | include/linux/xarray.h                                    | xa_init                                   | 1          |
|            | include/linux/xarray.h                                    | xa_init_flags                             | 1          |
|            | lib/xarray.c                                              | xa_load                                   | 1          |

### io-wq.c
| Source  | Library                                                   | Function Utilized                   | Times Used |
| ------- | --------------------------------------------------------- | ----------------------------------- | ---------- |
| io-wq.c | arch/parisc/kernel/firmware.c                             | __acquires                          | 1          |
|         | include/linux/wait.h                                      | __add_wait_queue                    | 1          |
|         | include/linux/cpumask.h                                   | alloc_cpumask_var                   | 2          |
|         | include/linux/atomic/atomic-instrumented.h                | atomic_dec                          | 5          |
|         | include/linux/atomic/atomic-instrumented.h                | atomic_dec_and_test                 | 2          |
|         | include/linux/atomic/atomic-instrumented.h                | atomic_inc                          | 6          |
|         | include/linux/atomic/atomic-instrumented.h                | atomic_or                           | 4          |
|         | include/linux/atomic/atomic-instrumented.h                | atomic_read                         | 5          |
|         | include/linux/atomic/atomic-instrumented.h                | atomic_set                          | 2          |
|         | drivers/comedi/drivers/ni_routing/tools/convert_c_to_py.c | BIT                                 | 1          |
|         | arch/x86/include/asm/kvm-x86-ops.h                        | BUILD_BUG_ON                        | 3          |
|         | arch/alpha/include/asm/bitops.h                           | clear_bit                           | 6          |
|         | arch/alpha/include/asm/bitops.h                           | clear_bit_unlock                    | 4          |
|         | arch/arm/mach-rpc/ecard.c                                 | complete                            | 2          |
|         | include/linux/sched.h                                     | cond_resched                        | 1          |
|         | drivers/gpu/drm/radeon/mkregtable.c                       | container_of                        | 10         |
|         | include/linux/cpuhotplug.h                                | cpuhp_setup_state_multi             | 1          |
|         | include/linux/cpuhotplug.h                                | cpuhp_state_add_instance_nocalls    | 1          |
|         | include/linux/cpuhotplug.h                                | cpuhp_state_remove_instance_nocalls | 1          |
|         | include/linux/cpumask.h                                   | cpumask_clear_cpu                   | 1          |
|         | include/linux/cpumask.h                                   | cpumask_copy                        | 2          |
|         | include/linux/cpumask.h                                   | cpumask_set_cpu                     | 1          |
|         | include/linux/cpumask.h                                   | cpumask_subset                      | 1          |
|         | include/linux/cpumask.h                                   | cpumask_test_cpu                    | 1          |
|         | include/linux/cpuset.h                                    | cpuset_cpus_allowed                 | 2          |
|         | kernel/fork.c                                             | create_io_thread                    | 2          |
|         | io_uring/io-wq.c                                          | create_io_worker                    | 2          |
|         | include/linux/kernel.h                                    | do_exit                             | 1          |
|         | drivers/greybus/svc_watchdog.c                            | do_work                             | 2          |
|         | include/linux/err.h                                       | ERR_PTR                             | 4          |
|         | include/linux/sched/signal.h                              | fatal_signal_pending                | 1          |
|         | arch/arm/include/asm/traps.h                              | fn                                  | 2          |
|         | include/linux/cpumask.h                                   | free_cpumask_var                    | 3          |
|         | arch/powerpc/sysdev/fsl_mpic_timer_wakeup.c               | free_work                           | 2          |
|         | arch/mips/include/asm/mips-r2-to-r6-emul.h                | func                                | 1          |
|         | kernel/signal.c                                           | get_signal                          | 1          |
|         | include/linux/sched/task.h                                | get_task_struct                     | 1          |
|         | include/linux/hash.h                                      | hash_ptr                            | 1          |
|         | include/linux/list.h                                      | hlist_entry_safe                    | 2          |
|         | include/linux/rculist_nulls.h                             | hlist_nulls_add_head_rcu            | 2          |
|         | include/linux/rculist_nulls.h                             | hlist_nulls_del_init_rcu            | 1          |
|         | include/linux/rculist_nulls.h                             | hlist_nulls_del_rcu                 | 1          |
|         | include/linux/rculist_nulls.h                             | hlist_nulls_for_each_entry_rcu      | 1          |
|         | drivers/bluetooth/hci_nokia.c                             | init_completion                     | 2          |
|         | include/linux/workqueue.h                                 | INIT_DELAYED_WORK                   | 1          |
|         | include/linux/list_nulls.h                                | INIT_HLIST_NULLS_HEAD               | 1          |
|         | drivers/gpu/drm/radeon/mkregtable.c                       | INIT_LIST_HEAD                      | 2          |
|         | include/linux/task_work.h                                 | init_task_work                      | 1          |
|         | io_uring/slist.h                                          | INIT_WQ_LIST                        | 1          |
|         | io_uring/io-wq.c                                          | io_acct_activate_free_worker        | 2          |
|         | io_uring/io-wq.c                                          | io_acct_cancel_pending_work         | 3          |
|         | io_uring/io-wq.c                                          | io_acct_cancel_running_work         | 1          |
|         | io_uring/io-wq.c                                          | io_acct_for_each_worker             | 2          |
|         | io_uring/io-wq.c                                          | __io_acct_run_queue                 | 2          |
|         | io_uring/io-wq.c                                          | io_acct_run_queue                   | 3          |
|         | io_uring/io-wq.c                                          | io_assign_current_work              | 3          |
|         | io_uring/io-wq.c                                          | io_get_acct                         | 2          |
|         | io_uring/io-wq.c                                          | io_get_next_work                    | 1          |
|         | io_uring/io-wq.c                                          | __io_get_work_hash                  | 4          |
|         | io_uring/io-wq.c                                          | io_get_work_hash                    | 2          |
|         | io_uring/io-wq.c                                          | io_init_new_worker                  | 2          |
|         | io_uring/io-wq.c                                          | io_queue_worker_create              | 2          |
|         | io_uring/io-wq.c                                          | io_run_cancel                       | 2          |
|         | io_uring/io_uring.h                                       | io_run_task_work                    | 2          |
|         | io_uring/io-wq.c                                          | io_should_retry_thread              | 2          |
|         | io_uring/io-wq.c                                          | io_wait_on_hash                     | 1          |
|         | io_uring/io-wq.c                                          | __io_worker_busy                    | 1          |
|         | io_uring/io-wq.c                                          | io_worker_cancel_cb                 | 2          |
|         | io_uring/io-wq.c                                          | io_worker_exit                      | 1          |
|         | io_uring/io-wq.c                                          | io_worker_get                       | 3          |
|         | io_uring/io-wq.c                                          | io_worker_handle_work               | 2          |
|         | io_uring/io-wq.c                                          | __io_worker_idle                    | 1          |
|         | io_uring/io-wq.c                                          | io_worker_ref_put                   | 9          |
|         | io_uring/io-wq.c                                          | io_worker_release                   | 8          |
|         | io_uring/io-wq.c                                          | io_work_get_acct                    | 1          |
|         | io_uring/io-wq.c                                          | io_wq_cancel_pending_work           | 2          |
|         | io_uring/io-wq.c                                          | io_wq_cancel_running_work           | 1          |
|         | io_uring/io-wq.c                                          | io_wq_cancel_tw_create              | 2          |
|         | io_uring/io-wq.c                                          | __io_wq_cpu_online                  | 2          |
|         | io_uring/io-wq.c                                          | io_wq_create_worker                 | 1          |
|         | io_uring/io-wq.h                                          | io_wq_current_is_worker             | 1          |
|         | io_uring/io-wq.c                                          | io_wq_dec_running                   | 2          |
|         | io_uring/io-wq.c                                          | io_wq_destroy                       | 1          |
|         | io_uring/io-wq.c                                          | io_wq_enqueue                       | 1          |
|         | io_uring/io-wq.c                                          | io_wq_exit_workers                  | 1          |
|         | io_uring/io-wq.c                                          | io_wq_for_each_worker               | 2          |
|         | io_uring/io-wq.c                                          | io_wq_get_acct                      | 7          |
|         | io_uring/io-wq.c                                          | io_wq_inc_running                   | 1          |
|         | io_uring/io-wq.c                                          | io_wq_insert_work                   | 1          |
|         | io_uring/io-wq.h                                          | __io_wq_is_hashed                   | 3          |
|         | io_uring/io-wq.h                                          | io_wq_is_hashed                     | 2          |
|         | io_uring/io-wq.h                                          | io_wq_put_hash                      | 2          |
|         | io_uring/io-wq.c                                          | io_wq_remove_pending                | 1          |
|         | io_uring/io-wq.c                                          | __io_wq_worker_cancel               | 1          |
|         | crypto/asymmetric_keys/x509_parser.h                      | IS_ERR                              | 2          |
|         | include/linux/slab.h                                      | kfree                               | 6          |
|         | include/linux/rcupdate.h                                  | kfree_rcu                           | 1          |
|         | include/linux/slab.h                                      | kzalloc                             | 2          |
|         | include/linux/compiler.h                                  | likely                              | 1          |
|         | include/linux/rculist.h                                   | list_add_tail_rcu                   | 1          |
|         | include/linux/list.h                                      | list_del_init                       | 3          |
|         | include/linux/rculist.h                                   | list_del_rcu                        | 1          |
|         | drivers/net/wireless/ath/ath11k/hal.h                     | list_empty                          | 1          |
|         | include/linux/rculist.h                                   | list_for_each_entry_rcu             | 1          |
|         | arch/mips/include/asm/octeon/cvmx-stxx-defs.h             | max_t                               | 1          |
|         | include/linux/jiffies.h                                   | msecs_to_jiffies                    | 1          |
|         | drivers/block/aoe/aoenet.c                                | __must_hold                         | 2          |
|         | include/linux/printk.h                                    | pr_warn_once                        | 1          |
|         | include/linux/err.h                                       | PTR_ERR                             | 2          |
|         | include/linux/sched/task.h                                | put_task_struct                     | 1          |
|         | io_uring/io-wq.c                                          | queue_create_worker_retry           | 2          |
|         | arch/alpha/include/asm/smp.h                              | raw_smp_processor_id                | 1          |
|         | include/linux/spinlock.h                                  | raw_spin_lock                       | 20         |
|         | include/linux/spinlock.h                                  | raw_spin_lock_init                  | 3          |
|         | include/linux/spinlock.h                                  | raw_spin_unlock                     | 26         |
|         | include/linux/rcupdate.h                                  | rcu_read_lock                       | 7          |
|         | include/linux/rcupdate.h                                  | rcu_read_unlock                     | 7          |
|         | include/linux/refcount.h                                  | refcount_dec_and_test               | 1          |
|         | include/linux/refcount.h                                  | refcount_inc                        | 1          |
|         | include/linux/refcount.h                                  | refcount_inc_not_zero               | 1          |
|         | include/linux/refcount.h                                  | refcount_set                        | 1          |
|         | arch/parisc/kernel/firmware.c                             | __releases                          | 1          |
|         | include/linux/workqueue.h                                 | schedule_delayed_work               | 1          |
|         | kernel/time/sleep_timeout.c                               | schedule_timeout                    | 1          |
|         | arch/alpha/include/asm/bitops.h                           | set_bit                             | 5          |
|         | include/linux/sched.h                                     | set_cpus_allowed_ptr                | 1          |
|         | include/linux/sched.h                                     | __set_current_state                 | 4          |
|         | include/linux/sched.h                                     | set_current_state                   | 1          |
|         | include/linux/bitops.h                                    | set_mask_bits                       | 1          |
|         | include/linux/sched/signal.h                              | __set_notify_signal                 | 2          |
|         | include/linux/sched.h                                     | set_task_comm                       | 1          |
|         | include/linux/sched/signal.h                              | signal_pending                      | 1          |
|         | drivers/acpi/acpica/utprint.c                             | snprintf                            | 1          |
|         | include/linux/spinlock.h                                  | spin_lock_irq                       | 3          |
|         | include/linux/spinlock.h                                  | spin_unlock_irq                     | 3          |
|         | include/linux/sched/signal.h                              | task_rlimit                         | 3          |
|         | kernel/task_work.c                                        | task_work_add                       | 1          |
|         | kernel/task_work.c                                        | task_work_cancel_match              | 2          |
|         | arch/alpha/include/asm/bitops.h                           | test_and_clear_bit                  | 1          |
|         | arch/alpha/include/asm/bitops.h                           | test_and_set_bit                    | 1          |
|         | arch/alpha/include/asm/bitops.h                           | test_and_set_bit_lock               | 1          |
|         | arch/x86/boot/bitops.h                                    | test_bit                            | 19         |
|         | include/linux/compiler.h                                  | unlikely                            | 1          |
|         | drivers/i2c/busses/i2c-pca-isa.c                          | wait_for_completion                 | 2          |
|         | include/linux/wait.h                                      | wake_up                             | 2          |
|         | kernel/sched/core.c                                       | wake_up_new_task                    | 1          |
|         | kernel/sched/core.c                                       | wake_up_process                     | 2          |
|         | include/asm-generic/bug.h                                 | WARN_ON_ONCE                        | 4          |
|         | include/linux/wait.h                                      | wq_has_sleeper                      | 2          |
|         | io_uring/slist.h                                          | wq_list_add_after                   | 1          |
|         | io_uring/slist.h                                          | wq_list_add_tail                    | 1          |
|         | io_uring/slist.h                                          | wq_list_cut                         | 1          |
|         | io_uring/slist.h                                          | wq_list_del                         | 2          |
|         | io_uring/slist.h                                          | wq_list_empty                       | 1          |
|         | io_uring/slist.h                                          | wq_list_for_each                    | 2          |
|         | io_uring/slist.h                                          | wq_next_work                        | 1          |

### kbuf.c
| Source File | Library/Header                           | Function                   | Times Used |
| ----------- | ---------------------------------------- | -------------------------- | ---------- |
| kbuf.c      | arch/arm64/include/asm/uaccess.h         | access_ok                  | 1          |
|             | arch/mips/boot/tools/relocs.h            | ARRAY_SIZE                 | 1          |
|             | include/linux/overflow.h                 | check_add_overflow         | 1          |
|             | include/linux/overflow.h                 | check_mul_overflow         | 1          |
|             | include/linux/sched.h                    | cond_resched               | 2          |
|             | include/linux/uaccess.h                  | copy_from_user             | 3          |
|             | include/linux/uaccess.h                  | copy_to_user               | 1          |
|             | include/linux/overflow.h                 | flex_array_size            | 1          |
|             | drivers/gpu/drm/i915/i915_vma_resource.h | guard                      | 1          |
|             | drivers/gpu/drm/radeon/mkregtable.c      | INIT_LIST_HEAD             | 2          |
|             | io_uring/kbuf.c                          | io_add_buffers             | 1          |
|             | io_uring/kbuf.c                          | io_buffer_add_list         | 2          |
|             | io_uring/kbuf.c                          | io_buffer_get_list         | 9          |
|             | io_uring/memmap.c                        | io_create_region_mmap_safe | 1          |
|             | io_uring/kbuf.c                          | io_destroy_bl              | 1          |
|             | io_uring/io_uring.h                      | io_file_can_poll           | 1          |
|             | io_uring/memmap.c                        | io_free_region             | 2          |
|             | io_uring/kbuf.c                          | io_kbuf_commit             | 3          |
|             | io_uring/kbuf.c                          | io_kbuf_drop_legacy        | 1          |
|             | io_uring/kbuf.c                          | io_kbuf_inc_commit         | 1          |
|             | include/linux/io_uring_types.h           | io_kiocb_to_cmd            | 4          |
|             | io_uring/kbuf.c                          | io_provided_buffer_select  | 2          |
|             | io_uring/kbuf.c                          | io_provided_buffers_select | 2          |
|             | io_uring/kbuf.c                          | io_put_bl                  | 3          |
|             | io_uring/kbuf.c                          | __io_put_kbuf_ring         | 1          |
|             | io_uring/memmap.h                        | io_region_get_ptr          | 1          |
|             | io_uring/kbuf.c                          | __io_remove_buffers        | 2          |
|             | io_uring/io_uring.h                      | io_req_set_res             | 2          |
|             | io_uring/kbuf.c                          | io_ring_buffer_select      | 1          |
|             | io_uring/kbuf.c                          | io_ring_buffers_peek       | 2          |
|             | io_uring/kbuf.c                          | io_ring_head_to_buf        | 4          |
|             | io_uring/io_uring.h                      | io_ring_submit_lock        | 5          |
|             | io_uring/io_uring.h                      | io_ring_submit_unlock      | 5          |
|             | arch/microblaze/mm/pgtable.c             | is_power_of_2              | 1          |
|             | include/linux/slab.h                     | kfree                      | 6          |
|             | include/linux/slab.h                     | kmalloc                    | 1          |
|             | include/linux/slab.h                     | kmalloc_array              | 1          |
|             | include/linux/slab.h                     | kzalloc                    | 2          |
|             | include/linux/compiler.h                 | likely                     | 1          |
|             | include/linux/list.h                     | list_add                   | 1          |
|             | drivers/gpu/drm/radeon/mkregtable.c      | list_add_tail              | 1          |
|             | include/linux/list.h                     | list_del                   | 2          |
|             | drivers/net/wireless/ath/ath11k/hal.h    | list_empty                 | 4          |
|             | include/linux/list.h                     | list_first_entry           | 2          |
|             | include/linux/lockdep.h                  | lockdep_assert_held        | 6          |
|             | arch/alpha/include/asm/string.h          | memset                     | 2          |
|             | include/linux/minmax.h                   | min_not_zero               | 1          |
|             | arch/powerpc/boot/types.h                | min_t                      | 3          |
|             | arch/powerpc/boot/page.h                 | PAGE_ALIGN                 | 1          |
|             | include/asm-generic/rwonce.h             | READ_ONCE                  | 8          |
|             | io_uring/io_uring.h                      | req_set_fail               | 2          |
|             | include/linux/cleanup.h                  | scoped_guard               | 3          |
|             | include/asm-generic/barrier.h            | smp_load_acquire           | 2          |
|             | include/linux/kernel.h                   | u64_to_user_ptr            | 4          |
|             | include/linux/compiler.h                 | unlikely                   | 11         |
|             | include/asm-generic/bug.h                | WARN_ON_ONCE               | 2          |
|             | lib/xarray.c                             | xa_erase                   | 3          |
|             | include/linux/xarray.h                   | xa_err                     | 1          |
|             | include/linux/xarray.h                   | xa_find                    | 1          |
|             | lib/xarray.c                             | xa_load                    | 2          |
|             | lib/xarray.c                             | xa_sto                     |

### memmap.c
| Source File | Library/Header                 | Function                       | Times Used |
| ----------- | ------------------------------ | ------------------------------ | ---------- |
| memmap.c    | io_uring/memmap.c              | io_region_mmap                 | 1          |
|             | include/linux/err.h            | IS_ERR                         | 5          |
|             | mm/memory.c                    | vm_insert_pages                | 1          |
|             | include/linux/fortify-string.h | memset                         | 1          |
|             | io_uring/memmap.h              | io_region_get_ptr              | 1          |
|             | include/linux/fortify-string.h | memcpy                         | 2          |
|             | io_uring/memmap.c              | io_region_pin_pages            | 1          |
|             | mm/gup.c                       | pin_user_pages_fast            | 1          |
|             | io_uring/memmap.c              | io_free_region                 | 1          |
|             | include/linux/slab.h           | kvfree                         | 3          |
|             | include/linux/mm.h             | vm_flags_set                   | 1          |
|             | include/asm-generic/bug.h      | WARN_ON_ONCE                   | 4          |
|             | io_uring/rsrc.c                | io_check_coalesce_buffer       | 1          |
|             | io_uring/memmap.c              | io_uring_validate_mmap_request | 3          |
|             | io_uring/memmap.c              | io_mem_alloc_compound          | 1          |
|             | include/linux/lockdep.h        | lockdep_assert_held            | 1          |
|             | io_uring/kbuf.c                | io_pbuf_get_region             | 1          |
|             | include/linux/overflow.h       | check_add_overflow             | 3          |
|             | mm/swap.c                      | release_pages                  | 2          |
|             | arch/arc/include/asm/arcregs.h | min                            | 1          |
|             | io_uring/memmap.c              | io_mmap_get_region             | 2          |
|             | include/asm-generic/getorder.h | get_order                      | 1          |
|             | io_uring/rsrc.c                | __io_account_mem               | 1          |
|             | include/linux/err.h            | ERR_PTR                        | 11         |
|             | io_uring/memmap.c              | io_region_init_ptr             | 1          |
|             | include/linux/slab.h           | kvmalloc_array                 | 2          |
|             | include/linux/cleanup.h        | guard                          | 4          |
|             | include/drm/drm_gem.h          | vmap                           | 1          |
|             | include/linux/gfp.h            | alloc_pages_bulk_node          | 1          |
|             | include/linux/fortify-string.h | memchr_inv                     | 1          |
|             | io_uring/memmap.c              | io_region_allocate_pages       | 1          |
|             | io_uring/memmap.c              | io_pin_pages                   | 1          |
|             | io_uring/memmap.c              | io_create_region               | 1          |
|             | mm/gup.c                       | unpin_user_pages               | 2          |
|             | io_uring/memmap.h              | io_region_is_set               | 1          |
|             | include/linux/gfp.h            | alloc_pages                    | 1          |
|             | include/linux/err.h            | PTR_ERR                        | 3          |
|             | io_uring/memmap.c              | io_region_validate_mmap        | 1          |
|             | include/linux/mm.h             | is_nommu_shared_mapping        | 1          |
|             | mm/mmap.c                      | mm_get_unmapped_area           | 1          |
|             | include/linux/dma-buf.h        | vunmap                         | 1          |
|             | include/linux/mm.h             | page_address                   | 2          |
|             | io_uring/rsrc.h                | __io_unaccount_mem             | 1          |

### msg_ring.c
### msg_ring.c
| Source File | Library/Header                   | Function                    | Times Used |
| ----------- | -------------------------------- | --------------------------- | ---------- |
| msg_ring.c  | include/linux/fs.h               | get_file                    | 1          |
|             | io_uring/msg_ring.c              | io_double_unlock_ctx        | 2          |
|             | include/linux/io_uring.h         | io_is_uring_fops            | 2          |
|             | include/linux/mutex.h            | mutex_lock                  | 1          |
|             | include/linux/compiler.h         | unlikely                    | 7          |
|             | include/linux/file.h             | fd_empty                    | 1          |
|             | mm/slub.c                        | kmem_cache_free             | 2          |
|             | io_uring/msg_ring.c              | io_msg_send_fd              | 1          |
|             | io_uring/msg_ring.c              | io_lock_external_ctx        | 2          |
|             | io_uring/filetable.c             | __io_fixed_fd_install       | 1          |
|             | io_uring/msg_ring.c              | io_msg_grab_file            | 1          |
|             | io_uring/rsrc.h                  | io_rsrc_node_lookup         | 1          |
|             | io_uring/io_uring.h              | io_ring_submit_unlock       | 1          |
|             | include/linux/task_work.h        | init_task_work              | 1          |
|             | io_uring/msg_ring.c              | io_msg_remote_post          | 1          |
|             | io_uring/io_uring.h              | io_req_queue_tw_complete    | 1          |
|             | include/linux/container_of.h     | container_of                | 1          |
|             | io_uring/io_uring.h              | io_ring_submit_lock         | 1          |
|             | io_uring/io_uring.c              | io_req_task_work_add_remote | 1          |
|             | include/linux/spinlock.h         | spin_unlock                 | 2          |
|             | include/linux/file.h             | fd_file                     | 2          |
|             | io_uring/msg_ring.c              | io_msg_install_complete     | 2          |
|             | include/linux/spinlock.h         | spin_trylock                | 2          |
|             | include/linux/mutex.h            | mutex_unlock                | 1          |
|             | include/linux/io_uring_types.h   | io_kiocb_to_cmd             | 8          |
|             | io_uring/alloc_cache.h           | io_alloc_cache_put          | 1          |
|             | tools/testing/vma/vma_internal.h | fput                        | 1          |
|             | io_uring/msg_ring.c              | io_msg_fd_remote            | 1          |
|             | include/linux/slab.h             | kmem_cache_alloc            | 1          |
|             | include/asm-generic/rwonce.h     | READ_ONCE                   | 8          |
|             | io_uring/alloc_cache.h           | io_alloc_cache_get          | 1          |
|             | io_uring/io_uring.h              | io_req_set_res              | 2          |
|             | io_uring/io_uring.c              | io_add_aux_cqe              | 1          |
|             | include/linux/cleanup.h          | CLASS                       | 1          |
|             | io_uring/msg_ring.c              | io_msg_need_remote          | 2          |
|             | io_uring/msg_ring.c              | io_msg_data_remote          | 1          |
|             | kernel/task_work.c               | task_work_add               | 1          |
|             | io_uring/msg_ring.c              | io_msg_ring_data            | 1          |
|             | include/linux/percpu-refcount.h  | percpu_ref_get              | 1          |
|             | io_uring/msg_ring.c              | __io_msg_ring_prep          | 2          |
|             | io_uring/msg_ring.c              | io_msg_get_kiocb            | 1          |
|             | include/linux/mutex.h            | mutex_trylock               | 1          |
|             | include/linux/percpu-refcount.h  | percpu_ref_put              | 1          |
|             | include/linux/io_uring_types.h   | cmd_to_io_kiocb             | 1          |
|             | io_uring/io_uring.h              | req_set_fail                | 2          |
|             | include/asm-generic/bug.h        | WARN_ON_ONCE                | 1          |
|             | io_uring/msg_ring.c              | __io_msg_ring_data          | 2          |
|             | io_uring/io_uring.c              | io_post_aux_cqe             | 2          |
|             | io_uring/filetable.h             | io_slot_file                | 1          |

### napi.c
| Source File | Library/Header               | Function                      | Times Used |
| ----------- | ---------------------------- | ----------------------------- | ---------- |
| napi.c      | include/linux/ktime.h        | ns_to_ktime                   | 2          |
|             | include/linux/slab.h         | kmalloc                       | 1          |
|             | io_uring/napi.c              | __io_napi_remove_stale        | 1          |
|             | include/linux/spinlock.h     | spin_lock                     | 1          |
|             | include/linux/ktime.h        | ktime_after                   | 1          |
|             | include/linux/rculist.h      | list_for_each_entry_rcu       | 2          |
|             | include/linux/minmax.h       | min_t                         | 1          |
|             | io_uring/napi.c              | io_napi_hash_find             | 3          |
|             | io_uring/napi.c              | __io_napi_del_id              | 1          |
|             | include/linux/ktime.h        | ktime_sub                     | 1          |
|             | io_uring/io_uring.h          | io_has_work                   | 1          |
|             | include/net/busy_poll.h      | napi_id_valid                 | 2          |
|             | include/linux/uaccess.h      | copy_to_user                  | 2          |
|             | include/linux/cleanup.h      | scoped_guard                  | 3          |
|             | io_uring/napi.c              | __io_napi_do_busy_loop        | 2          |
|             | include/linux/ktime.h        | ktime_add                     | 1          |
|             | include/linux/hashtable.h    | hash_del_rcu                  | 3          |
|             | include/linux/rculist.h      | hlist_for_each_entry_rcu      | 1          |
|             | io_uring/napi.c              | io_napi_busy_loop_should_end  | 1          |
|             | include/linux/hashtable.h    | hash_min                      | 2          |
|             | io_uring/napi.c              | io_napi_free                  | 1          |
|             | io_uring/napi.c              | __io_napi_add_id              | 1          |
|             | io_uring/napi.c              | static_tracking_do_busy_loop  | 1          |
|             | include/linux/list.h         | list_for_each_entry           | 2          |
|             | io_uring/napi.c              | io_napi_busy_loop_timeout     | 1          |
|             | include/linux/hashtable.h    | HASH_BITS                     | 2          |
|             | io_uring/napi.c              | io_napi_remove_stale          | 2          |
|             | include/linux/spinlock.h     | spin_lock_init                | 1          |
|             | include/linux/jiffies.h      | time_after                    | 2          |
|             | include/linux/list.h         | list_is_singular              | 1          |
|             | net/core/dev.c               | napi_busy_loop_rcu            | 2          |
|             | include/linux/spinlock.h     | spin_unlock                   | 2          |
|             | include/asm-generic/rwonce.h | WRITE_ONCE                    | 7          |
|             | include/linux/rculist.h      | INIT_LIST_HEAD_RCU            | 1          |
|             | include/linux/compiler.h     | unlikely                      | 1          |
|             | include/linux/uaccess.h      | copy_from_user                | 1          |
|             | io_uring/io_uring.h          | io_should_wake                | 1          |
|             |                              | signal_pending                | 1          |
|             | include/linux/rculist.h      | list_del_rcu                  | 2          |
|             | io_uring/napi.c              | net_to_ktime                  | 2          |
|             | io_uring/napi.c              | dynamic_tracking_do_busy_loop | 1          |
|             | include/linux/slab.h         | kfree                         | 1          |
|             | io_uring/io_uring.h          | io_get_time                   | 1          |
|             | include/net/busy_poll.h      | busy_loop_current_time        | 2          |
|             | include/linux/rculist.h      | list_add_tail_rcu             | 1          |
|             | io_uring/napi.c              | io_napi_register_napi         | 1          |
|             | io_uring/napi.c              | io_napi_blocking_busy_loop    | 1          |
|             | include/asm-generic/rwonce.h | READ_ONCE                     | 7          |
|             | include/linux/rcupdate.h     | kfree_rcu                     | 3          |
|             | include/linux/list.h         | INIT_LIST_HEAD                | 1          |
|             | include/linux/rculist.h      | hlist_add_tail_rcu            | 1          |
|             | include/linux/cleanup.h      | guard                         | 3          |
|             | include/linux/list.h         | list_empty_careful            | 1          |
|             | include/linux/ktime.h        | ktime_to_us                   | 2          |

### net.c
| Source File | Library/Header                       | Function                    | Times Used |
| ----------- | ------------------------------------ | --------------------------- | ---------- |
| net.c       | arch/x86/include/asm/kvm-x86-ops.h   | BUILD_BUG_ON                | 1          |
|             | include/linux/bvec.h                 | bvec_iter_advance_single    | 1          |
|             | include/linux/overflow.h             | check_add_overflow          | 2          |
|             | arch/s390/include/asm/compat.h       | compat_ptr                  | 2          |
|             | include/linux/uaccess.h              | copy_from_user              | 3          |
|             | net/socket.c                         | __copy_msghdr               | 1          |
|             | include/linux/uaccess.h              | copy_to_user                | 1          |
|             | net/socket.c                         | do_accept                   | 1          |
|             | fs/file.c                            | fd_install                  | 2          |
|             | net/compat.c                         | __get_compat_msghdr         | 1          |
|             | fs/file.c                            | __get_unused_fd_flags       | 2          |
|             | lib/iov_iter.c                       | __import_iovec              | 1          |
|             | lib/iov_iter.c                       | import_ubuf                 | 4          |
|             | io_uring/alloc_cache.h               | io_alloc_cache_put          | 1          |
|             | io_uring/rsrc.h                      | io_alloc_cache_vec_kasan    | 1          |
|             | io_uring/notif.c                     | io_alloc_notif              | 1          |
|             | io_uring/kbuf.c                      | io_buffer_select            | 2          |
|             | io_uring/kbuf.c                      | io_buffers_peek             | 1          |
|             | io_uring/kbuf.c                      | io_buffers_select           | 1          |
|             | io_uring/net.c                       | io_bundle_nbufs             | 2          |
|             | io_uring/net.c                       | io_compat_msg_copy_hdr      | 1          |
|             | io_uring/net.c                       | io_copy_msghdr_from_user    | 1          |
|             | io_uring/kbuf.h                      | io_do_buffer_select         | 5          |
|             | io_uring/filetable.c                 | io_fixed_fd_install         | 2          |
|             | io_uring/rsrc.c                      | io_import_reg_buf           | 1          |
|             | io_uring/rsrc.c                      | io_import_reg_vec           | 1          |
|             | io_uring/io_uring.h                  | io_is_compat                | 5          |
|             | io_uring/kbuf.h                      | io_kbuf_recycle             | 5          |
|             | include/linux/io_uring_types.h       | io_kiocb_to_cmd             | 36         |
|             | io_uring/net.c                       | io_msg_alloc_async          | 5          |
|             | io_uring/net.c                       | io_msg_copy_hdr             | 2          |
|             | io_uring/net.c                       | io_mshot_prep_retry         | 2          |
|             | io_uring/net.c                       | io_net_import_vec           | 2          |
|             | io_uring/net.c                       | io_netmsg_iovec_free        | 3          |
|             | io_uring/net.c                       | io_netmsg_recycle           | 1          |
|             | io_uring/net.c                       | io_net_retry                | 6          |
|             | io_uring/notif.h                     | io_notif_account_mem        | 1          |
|             | io_uring/notif.h                     | io_notif_flush              | 3          |
|             | io_uring/notif.h                     | io_notif_to_data            | 3          |
|             | io_uring/rsrc.c                      | io_prep_reg_iovec           | 1          |
|             | io_uring/kbuf.h                      | io_put_kbuf                 | 2          |
|             | io_uring/kbuf.h                      | io_put_kbufs                | 2          |
|             | io_uring/net.c                       | io_recv_buf_select          | 1          |
|             | io_uring/net.c                       | io_recv_finish              | 2          |
|             | io_uring/net.c                       | io_recvmsg_copy_hdr         | 1          |
|             | io_uring/net.c                       | io_recvmsg_mshot_prep       | 1          |
|             | io_uring/net.c                       | io_recvmsg_multishot        | 1          |
|             | io_uring/net.c                       | io_recvmsg_prep_multishot   | 1          |
|             | io_uring/net.c                       | io_recvmsg_prep_setup       | 1          |
|             | io_uring/net.c                       | io_req_msg_cleanup          | 6          |
|             | io_uring/io_uring.c                  | io_req_post_cqe             | 3          |
|             | io_uring/io_uring.h                  | io_req_set_res              | 13         |
|             | io_uring/net.c                       | io_send_finish              | 1          |
|             | io_uring/net.c                       | io_sendmsg_setup            | 2          |
|             | io_uring/net.c                       | io_send_select_buffer       | 1          |
|             | io_uring/net.c                       | io_send_setup               | 2          |
|             | io_uring/net.c                       | io_send_zc_import           | 1          |
|             | io_uring/io_uring.h                  | io_uring_alloc_async_data   | 1          |
|             | io_uring/rsrc.c                      | io_vec_free                 | 3          |
|             | io_uring/rsrc.h                      | io_vec_reset_iovec          | 1          |
|             | include/linux/uio.h                  | iov_iter_count              | 7          |
|             | lib/iov_iter.c                       | iov_iter_init               | 2          |
|             | include/linux/uio.h                  | iov_iter_ubuf               | 1          |
|             | io_uring/zcrx.c                      | io_zcrx_recv                | 1          |
|             | crypto/asymmetric_keys/x509_parser.h | IS_ERR                      | 2          |
|             | include/linux/uio.h                  | iter_iov                    | 1          |
|             | include/linux/uio.h                  | iter_is_ubuf                | 1          |
|             | include/linux/slab.h                 | kfree                       | 1          |
|             | arch/alpha/include/asm/string.h      | memset                      | 1          |
|             | arch/arc/include/asm/arcregs.h       | min                         | 1          |
|             | include/linux/minmax.h               | min_not_zero                | 2          |
|             | arch/powerpc/boot/types.h            | min_t                       | 1          |
|             | net/socket.c                         | move_addr_to_kernel         | 3          |
|             | include/linux/bvec.h                 | mp_bvec_iter_bvec           | 1          |
|             | drivers/gpu/drm/radeon/mkregtable.c  | offsetof                    | 1          |
|             | arch/powerpc/boot/page.h             | PAGE_ALIGN                  | 1          |
|             | include/linux/err.h                  | PTR_ERR                     | 2          |
|             | fs/file.c                            | put_unused_fd               | 2          |
|             | include/asm-generic/rwonce.h         | READ_ONCE                   | 36         |
|             | io_uring/io_uring.h                  | req_has_async_data          | 1          |
|             | io_uring/io_uring.h                  | req_set_fail                | 14         |
|             | arch/parisc/include/asm/processor.h  | rlimit                      | 2          |
|             | include/linux/skbuff.h               | __skb_fill_page_desc_noacc  | 1          |
|             | include/linux/skbuff.h               | skb_shinfo                  | 1          |
|             | include/linux/skbuff.h               | skb_zcopy_downgrade_managed | 1          |
|             | include/linux/skbuff.h               | skb_zcopy_managed           | 1          |
|             | include/net/sock.h                   | sock_error                  | 1          |
|             | net/socket.c                         | sock_from_file              | 11         |
|             | net/socket.c                         | sock_recvmsg                | 2          |
|             | net/socket.c                         | sock_sendmsg                | 2          |
|             | net/socket.c                         | __sys_bind_socket           | 1          |
|             | net/socket.c                         | __sys_connect_file          | 1          |
|             | net/socket.c                         | __sys_listen_socket         | 1          |
|             | net/socket.c                         | __sys_recvmsg_sock          | 1          |
|             | net/socket.c                         | __sys_sendmsg_sock          | 2          |
|             | net/socket.c                         | __sys_shutdown_sock         | 1          |
|             | net/socket.c                         | __sys_socket_file           | 1          |
|             | arch/x86/boot/bitops.h               | test_bit                    | 2          |
|             | include/linux/kernel.h               | u64_to_user_ptr             | 8          |
|             | include/linux/compiler.h             | unlikely                    | 47         |
|             | arch/arm64/include/asm/uaccess.h     | unsafe_get_user             | 6          |
|             | arch/arm64/include/asm/uaccess.h     | user_access_begin           | 1          |
|             | arch/arm64/include/asm/uaccess.h     | user_access_end             | 2          |
|             | include/asm-generic/bug.h            | WARN_ON_ONCE                | 2          |
|             | net/core/datagram.c                  | zerocopy_fill_skb_from_iter | 2          |

### nop.c
| Source File | Library/Header                 | Function           | Times Used |
| ----------- | ------------------------------ | ------------------ | ---------- |
| nop.c       | include/asm-generic/rwonce.h   | READ_ONCE          | 4          |
|             | io_uring/io_uring.c            | io_file_get_fixed  | 1          |
|             | io_uring/io_uring.h            | io_req_set_res     | 1          |
|             | io_uring/io_uring.c            | io_file_get_normal | 1          |
|             | include/linux/io_uring_types.h | io_kiocb_to_cmd    | 2          |
|             | io_uring/rsrc.c                | io_find_buf_node   | 1          |
|             | io_uring/io_uring.h            | req_set_fail       | 1          |

### notif.c
| Source File | Library/Header                 | Function               | Times Used |
| ----------- | ------------------------------ | ---------------------- | ---------- |
| notif.c     | io_uring/notif.h               | io_notif_to_data       | 2          |
|             | include/asm-generic/rwonce.h   | WRITE_ONCE             | 2          |
|             | include/linux/skbuff.h         | skb_zcopy_init         | 1          |
|             | include/linux/refcount.h       | refcount_set           | 1          |
|             | include/linux/container_of.h   | container_of           | 3          |
|             | include/linux/compiler.h       | unlikely               | 6          |
|             | include/linux/skbuff.h         | net_zcopy_get          | 2          |
|             | include/linux/compiler_types.h | __must_hold            | 1          |
|             | include/linux/io_uring_types.h | cmd_to_io_kiocb        | 4          |
|             | io_uring/io_uring.c            | io_req_task_complete   | 1          |
|             | io_uring/notif.c               | io_tx_ubuf_complete    | 1          |
|             | include/linux/refcount.h       | refcount_dec_and_test  | 1          |
|             | io_uring/io_uring.h            | io_alloc_req           | 1          |
|             | include/linux/refcount.h       | refcount_read          | 1          |
|             | include/linux/skbuff.h         | skb_zcopy              | 1          |
|             | io_uring/io_uring.c            | __io_req_task_work_add | 1          |
|             | io_uring/io_uring.h            | io_get_task_refs       | 1          |
|             | include/linux/lockdep.h        | lockdep_assert         | 1          |
|             | io_uring/rsrc.h                | __io_unaccount_mem     | 1          |

### opdef.c
| Source  | Library                                             | Function Utilized | Times Used |
| ------- | --------------------------------------------------- | ----------------- | ---------- |
| opdef.c | arch/alpha/kernel/perf_event.c                      | ARRAY_SIZE        | 3          |
|         | include/linux/build_bug.h                           | BUILD_BUG_ON      | 2          |
|         | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE      | 2          |
|         | arch/mips/include/asm/bug.h                         | BUG_ON            | 2          |  |

### openclose.c
| Source      | Library                                             | Function Utilized      | Times Used |
| ----------- | --------------------------------------------------- | ---------------------- | ---------- |
| openclose.c | include/linux/io_uring_types.h                      | io_kiocb_to_cmd        | 10         |
|             | .vmlinux.export.c                                   | receive_fd             | 1          |
|             | io_uring/openclose.c                                | io_close_fixed         | 2          |
|             | include/linux/kernel.h                              | u64_to_user_ptr        | 2          |
|             | io_uring/advise.c                                   | req_set_fail           | 3          |
|             | include/linux/io_uring.h                            | io_is_uring_fops       | 1          |
|             | fs/internal.h                                       | build_open_flags       | 1          |
|             | io_uring/cancel.c                                   | io_ring_submit_unlock  | 1          |
|             | drivers/usb/class/cdc-wdm.c                         | READ_ONCE              | 10         |
|             | drivers/gpu/drm/gma500/framebuffer.c                | IS_ERR                 | 2          |
|             | .vmlinux.export.c                                   | putname                | 2          |
|             | drivers/fwctl/main.c                                | copy_struct_from_user  | 1          |
|             | arch/parisc/include/asm/processor.h                 | rlimit                 | 1          |
|             | fs/file.c                                           | files_lookup_fd_locked | 1          |
|             | io_uring/filetable.h                                | io_fixed_fd_install    | 1          |
|             | fs/internal.h                                       | do_filp_open           | 1          |
|             | io_uring/opdef.c                                    | io_openat2             | 2          |
|             | io_uring/filetable.h                                | io_fixed_fd_remove     | 1          |
|             | fs/internal.h                                       | file_close_fd_locked   | 1          |
|             | include/linux/fcntl.h                               | force_o_largefile      | 1          |
|             | fs/internal.h                                       | build_open_how         | 1          |
|             | crypto/af_alg.c                                     | getname                | 1          |
|             | drivers/accel/habanalabs/common/hw_queue.c          | spin_unlock            | 3          |
|             | io_uring/advise.c                                   | io_req_set_res         | 3          |
|             | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE           | 1          |
|             | .vmlinux.export.c                                   | put_unused_fd          | 1          |
|             | io_uring/cancel.c                                   | io_ring_submit_lock    | 1          |
|             | .vmlinux.export.c                                   | filp_close             | 1          |
|             | drivers/accel/habanalabs/common/hw_queue.c          | spin_lock              | 1          |
|             | drivers/usb/class/cdc-wdm.c                         | PTR_ERR                | 2          |
|             | .vmlinux.export.c                                   | fd_install             | 1          |
|             | drivers/net/ethernet/sun/sunvnet_common.c           | unlikely               | 2          |
|             | io_uring/openclose.c                                | io_openat_force_async  | 3          |

### poll.c
| Source | Library                                             | Function Utilized              | Times Used |
| ------ | --------------------------------------------------- | ------------------------------ | ---------- |
| poll.c | io_uring/io_uring.h                                 | io_req_defer_failed            | 1          |
|        | arch/arm64/include/asm/atomic.h                     | atomic_sub_return              | 1          |
|        | net/ipv4/fib_semantics.c                            | hlist_add_head                 | 1          |
|        | drivers/infiniband/hw/bnxt_re/ib_verbs.c            | INIT_LIST_HEAD                 | 1          |
|        | io_uring/io_uring.h                                 | io_req_post_cqe                | 1          |
|        | io_uring/poll.c                                     | io_req_alloc_apoll             | 2          |
|        | io_uring/poll.c                                     | io_poll_get_single             | 3          |
|        | io_uring/poll.c                                     | io_poll_get_ownership_slowpath | 2          |
|        | fs/aio.c                                            | demangle_poll                  | 1          |
|        | io_uring/poll.c                                     | wqe_to_req                     | 2          |
|        | arch/arm/probes/kprobes/opt-arm.c                   | list_del_init                  | 3          |
|        | io_uring/poll.c                                     | io_poll_disarm                 | 2          |
|        | io_uring/poll.c                                     | io_poll_parse_events           | 3          |
|        | io_uring/cancel.c                                   | io_ring_submit_lock            | 3          |
|        | .vmlinux.export.c                                   | add_wait_queue                 | 1          |
|        | io_uring/poll.c                                     | io_poll_find                   | 3          |
|        | io_uring/io_uring.h                                 | io_req_task_complete           | 2          |
|        | drivers/net/ethernet/sun/sunvnet_common.c           | rcu_read_unlock                | 2          |
|        | io_uring/io_uring.h                                 | io_match_task_safe             | 1          |
|        | io_uring/poll.c                                     | io_poll_mark_cancelled         | 4          |
|        | drivers/usb/class/cdc-wdm.c                         | spin_unlock_irq                | 2          |
|        | io_uring/poll.c                                     | trace_io_uring_task_add        | 1          |
|        | include/linux/wait.h                                | key_to_poll                    | 1          |
|        | arch/x86/kernel/cpu/resctrl/pseudo_lock.c           | GENMASK                        | 1          |
|        | arch/arm64/include/asm/atomic.h                     | atomic_or                      | 1          |
|        | io_uring/poll.c                                     | io_poll_cancel_req             | 3          |
|        | io_uring/advise.c                                   | req_set_fail                   | 4          |
|        | io_uring/cancel.h                                   | io_cancel_req_match            | 1          |
|        | include/linux/list.h                                | hlist_for_each_entry_safe      | 1          |
|        | io_uring/io_uring.c                                 | io_file_can_poll               | 1          |
|        | include/asm-generic/barrier.h                       | smp_store_release              | 1          |
|        | arch/x86/kernel/apic/vector.c                       | hlist_del_init                 | 1          |
|        | drivers/accel/drm_accel.c                           | atomic_fetch_inc               | 2          |
|        | .vmlinux.export.c                                   | kfree                          | 2          |
|        | include/linux/lockdep.h                             | lockdep_assert_held            | 2          |
|        | io_uring/poll.c                                     | io_poll_remove_entry           | 3          |
|        | arch/mips/net/bpf_jit_comp32.c                      | atomic_cmpxchg                 | 1          |
|        | fs/aio.c                                            | mangle_poll                    | 2          |
|        | arch/arm64/include/asm/atomic.h                     | atomic_andnot                  | 1          |
|        | io_uring/poll.c                                     | io_poll_remove_entries         | 6          |
|        | drivers/net/wireless/ath/carl9170/debug.c           | atomic_read                    | 2          |
|        | io_uring/poll.c                                     | io_init_poll_iocb              | 3          |
|        | drivers/usb/class/cdc-wdm.c                         | spin_lock_irq                  | 2          |
|        | io_uring/cancel.c                                   | io_ring_submit_unlock          | 3          |
|        | drivers/hv/mshv_eventfd.c                           | vfs_poll                       | 5          |
|        | drivers/usb/class/cdc-wdm.c                         | READ_ONCE                      | 5          |
|        | block/blk-mq.c                                      | init_waitqueue_func_entry      | 1          |
|        | io_uring/poll.c                                     | io_poll_check_events           | 2          |
|        | io_uring/futex.c                                    | io_req_task_work_add           | 1          |
|        | include/linux/swab.h                                | swahw32                        | 1          |
|        | io_uring/futex.c                                    | io_tw_lock                     | 1          |
|        | .vmlinux.export.c                                   | add_wait_queue_exclusive       | 1          |
|        | io_uring/io_uring.h                                 | io_req_task_submit             | 2          |
|        | drivers/net/ethernet/sun/sunvnet_common.c           | rcu_read_lock                  | 4          |
|        | io_uring/poll.c                                     | io_poll_can_finish_inline      | 5          |
|        | io_uring/io_uring.h                                 | io_poll_issue                  | 1          |
|        | io_uring/advise.c                                   | io_req_set_res                 | 6          |
|        | io_uring/poll.c                                     | io_poll_double_prepare         | 2          |
|        | io_uring/poll.c                                     | io_poll_add_hash               | 3          |
|        | io_uring/poll.c                                     | io_poll_req_insert             | 2          |
|        | arch/arm/include/asm/spectre.h                      | BIT                            | 2          |
|        | arch/riscv/kernel/module.c                          | INIT_HLIST_NODE                | 1          |
|        | io_uring/poll.c                                     | io_pollfree_wake               | 2          |
|        | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE                   | 2          |
|        | io_uring/poll.c                                     | io_poll_execute                | 3          |
|        | arch/x86/kvm/svm/avic.c                             | hash_del                       | 2          |
|        | include/linux/list.h                                | hlist_for_each_entry           | 2          |
|        | io_uring/opdef.c                                    | io_poll_add                    | 2          |
|        | io_uring/io_uring.c                                 | io_should_terminate_tw         | 1          |
|        | io_uring/alloc_cache.h                              | io_cache_alloc                 | 1          |
|        | kernel/trace/trace_events.c                         | atomic_set                     | 1          |
|        | io_uring/poll.c                                     | wqe_is_double                  | 2          |
|        | io_uring/io_uring.c                                 | io_kbuf_recycle                | 3          |
|        | drivers/net/ethernet/sun/sunvnet_common.c           | unlikely                       | 9          |
|        | io_uring/poll.c                                     | io_poll_file_find              | 2          |
|        | include/linux/io_uring_types.h                      | io_kiocb_to_cmd                | 8          |
|        | io_uring/cancel.c                                   | io_cancel_match_sequence       | 1          |
|        | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_gfx_v10.c  | kmalloc                        | 2          |
|        | io_uring/poll.c                                     | io_poll_get_double             | 2          |
|        | arch/arm64/include/asm/atomic.h                     | atomic_fetch_or                | 1          |
|        | io_uring/poll.c                                     | io_poll_get_ownership          | 5          |
|        | io_uring/poll.c                                     | trace_io_uring_poll_arm        | 1          |
|        | io_uring/napi.h                                     | io_napi_add                    | 2          |
|        | drivers/accel/habanalabs/common/hw_queue.c          | container_of                   | 3          |
|        | include/linux/hash.h                                | hash_long                      | 2          |
|        | include/asm-generic/barrier.h                       | smp_load_acquire               | 2          |

### register.c
| Source     | Library                                             | Function Utilized            | Times Used |
| ---------- | --------------------------------------------------- | ---------------------------- | ---------- |
| register.c | kernel/trace/trace_events.c                         | refcount_inc                 | 1          |
|            | include/linux/io_uring.h                            | io_is_uring_fops             | 1          |
|            | io_uring/register.c                                 | io_probe                     | 2          |
|            | .vmlinux.export.c                                   | mutex_unlock                 | 9          |
|            | io_uring/sqpoll.h                                   | io_sq_thread_park            | 1          |
|            | drivers/dma/acpi-dma.c                              | kzalloc                      | 1          |
|            | io_uring/io_uring.c                                 | io_region_get_ptr            | 3          |
|            | drivers/accel/habanalabs/common/hw_queue.c          | spin_unlock                  | 1          |
|            | io_uring/register.c                                 | io_register_clock            | 2          |
|            | arch/x86/kernel/cpu/resctrl/rdtgroup.c              | put_cred                     | 2          |
|            | arch/mips/kernel/mips-mt-fpaff.c                    | get_task_struct              | 1          |
|            | include/asm-generic/rwonce.h                        | WRITE_ONCE                   | 12         |
|            | arch/arm/common/bL_switcher.c                       | cpumask_clear                | 1          |
|            | io_uring/opdef.h                                    | io_uring_op_supported        | 1          |
|            | arch/riscv/kernel/sys_hwprobe.c                     | cpumask_size                 | 2          |
|            | io_uring/register.c                                 | io_register_iowq_aff         | 2          |
|            | drivers/gpu/drm/gma500/framebuffer.c                | IS_ERR                       | 2          |
|            | kernel/trace/trace_events.c                         | atomic_set                   | 1          |
|            | include/linux/cred.h                                | get_current_cred             | 1          |
|            | include/linux/nospec.h                              | array_index_nospec           | 2          |
|            | include/linux/kernel.h                              | u64_to_user_ptr              | 1          |
|            | include/linux/cpumask.h                             | free_cpumask_var             | 2          |
|            | .vmlinux.export.c                                   | memchr_inv                   | 3          |
|            | io_uring/kbuf.h                                     | io_register_pbuf_ring        | 1          |
|            | io_uring/msg_ring.h                                 | io_uring_sync_msg_ring       | 1          |
|            | drivers/net/ethernet/sun/sunvnet_common.c           | unlikely                     | 3          |
|            | io_uring/rsrc.h                                     | io_sqe_buffers_register      | 1          |
|            | drivers/accel/habanalabs/common/hw_queue.c          | spin_lock                    | 1          |
|            | drivers/net/wireless/ath/carl9170/debug.c           | atomic_read                  | 1          |
|            | io_uring/rsrc.h                                     | io_register_clone_buffers    | 1          |
|            | include/linux/cpumask_types.h                       | cpumask_bits                 | 1          |
|            | io_uring/tctx.h                                     | io_ringfd_register           | 1          |
|            | io_uring/napi.h                                     | io_register_napi             | 1          |
|            | io_uring/filetable.h                                | io_register_file_alloc_range | 1          |
|            | drivers/gpu/drm/radeon/mkregtable.c                 | list_for_each_entry          | 1          |
|            | arch/mips/kernel/mips-mt-fpaff.c                    | alloc_cpumask_var            | 1          |
|            | .vmlinux.export.c                                   | kfree                        | 2          |
|            | include/linux/compat.h                              | compat_get_bitmap            | 1          |
|            | .vmlinux.export.c                                   | mutex_lock                   | 8          |
|            | io_uring/sqpoll.h                                   | io_sq_thread_unpark          | 1          |
|            | drivers/accel/habanalabs/common/memory.c            | get_file                     | 1          |
|            | arch/sh/kernel/traps_32.c                           | copy_to_user                 | 5          |
|            | include/linux/xarray.h                              | XA_LIMIT                     | 1          |
|            | io_uring/register.c                                 | io_register_iowq_max_workers | 2          |
|            | io_uring/sqpoll.h                                   | io_sqpoll_wq_cpu_affinity    | 1          |
|            | arch/powerpc/boot/page.h                            | PAGE_ALIGN                   | 2          |
|            | drivers/usb/class/cdc-wdm.c                         | READ_ONCE                    | 7          |
|            | .vmlinux.export.c                                   | fget                         | 1          |
|            | io_uring/sqpoll.h                                   | io_put_sq_data               | 2          |
|            | arch/alpha/kernel/perf_event.c                      | ARRAY_SIZE                   | 3          |
|            | drivers/accel/habanalabs/common/habanalabs.h        | array_size                   | 3          |
|            | io_uring/kbuf.h                                     | io_unregister_pbuf_ring      | 1          |
|            | io_uring/register.c                                 | io_parse_restrictions        | 2          |
|            | io_uring/zcrx.h                                     | io_register_zcrx_ifq         | 1          |
|            | io_uring/register.h                                 | io_unregister_personality    | 2          |
|            | io_uring/register.c                                 | io_register_mem_region       | 2          |
|            | io_uring/tctx.h                                     | io_ringfd_unregister         | 1          |
|            | io_uring/register.c                                 | swap_old                     | 3          |
|            | io_uring/rsrc.h                                     | io_register_rsrc             | 2          |
|            | .vmlinux.export.c                                   | fput                         | 3          |
|            | io_uring/io_uring.h                                 | io_activate_pollwq           | 1          |
|            | io_uring/register.c                                 | io_register_enable_rings     | 2          |
|            | io_uring/eventfd.h                                  | io_eventfd_unregister        | 1          |
|            | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE                 | 2          |
|            | io_uring/register.c                                 | io_uring_register_blind      | 2          |
|            | io_uring/register.c                                 | io_register_resize_rings     | 2          |
|            | .vmlinux.export.c                                   | memset                       | 4          |
|            | io_uring/rsrc.h                                     | io_sqe_buffers_unregister    | 1          |
|            | .vmlinux.export.c                                   | memdup_user                  | 1          |
|            | io_uring/io-wq.h                                    | io_wq_max_workers            | 2          |
|            | io_uring/rsrc.h                                     | io_register_files_update     | 1          |
|            | io_uring/io_uring.h                                 | rings_size                   | 1          |
|            | io_uring/memmap.h                                   | io_create_region_mmap_safe   | 3          |
|            | include/linux/wait.h                                | wake_up                      | 1          |
|            | io_uring/rsrc.h                                     | io_sqe_files_unregister      | 1          |
|            | io_uring/io_uring.h                                 | io_uring_fill_params         | 1          |
|            | io_uring/register.c                                 | io_unregister_iowq_aff       | 2          |
|            | .vmlinux.export.c                                   | xa_erase                     | 1          |
|            | io_uring/cancel.h                                   | io_sync_cancel               | 1          |
|            | block/blk-wbt.c                                     | wq_has_sleeper               | 2          |
|            | drivers/usb/class/cdc-wdm.c                         | PTR_ERR                      | 2          |
|            | drivers/md/md.c                                     | percpu_ref_is_dying          | 1          |
|            | arch/sh/kernel/traps_32.c                           | copy_from_user               | 8          |
|            | io_uring/eventfd.h                                  | io_eventfd_register          | 2          |
|            | io_uring/register.c                                 | io_register_free_rings       | 6          |
|            | io_uring/register.c                                 | io_register_restrictions     | 2          |
|            | io_uring/napi.h                                     | io_unregister_napi           | 1          |
|            | include/linux/compat.h                              | in_compat_syscall            | 1          |
|            | io_uring/register.c                                 | io_register_personality      | 2          |
|            | io_uring/rsrc.h                                     | io_register_rsrc_update      | 2          |
|            | io_uring/register.c                                 | trace_io_uring_register      | 1          |
|            | include/linux/build_bug.h                           | BUILD_BUG_ON                 | 1          |
|            | io_uring/memmap.h                                   | io_free_region               | 3          |
|            | arch/x86/boot/bitops.h                              | test_bit                     | 1          |
|            | drivers/accel/amdxdna/amdxdna_ctx.c                 | xa_alloc_cyclic              | 1          |
|            | io_uring/memmap.c                                   | io_region_is_set             | 1          |
|            | drivers/gpu/drm/amd/display/include/vector.h        | struct_size                  | 1          |
|            | io_uring/register.h                                 | io_uring_register_get_file   | 2          |
|            | io_uring/io-wq.h                                    | io_wq_cpu_affinity           | 1          |
|            | io_uring/kbuf.h                                     | io_register_pbuf_status      | 1          |
|            | drivers/gpu/drm/gma500/framebuffer.c                | ERR_PTR                      | 3          |
|            | io_uring/rsrc.h                                     | io_sqe_files_register        | 1          |

### rsrc.c
| Source | Library                                             | Function Utilized                | Times Used |
| ------ | --------------------------------------------------- | -------------------------------- | ---------- |
| rsrc.c | io_uring/filetable.c                                | io_file_bitmap_set               | 2          |
|        | include/linux/io_uring_types.h                      | io_kiocb_to_cmd                  | 3          |
|        | io_uring/rsrc.c                                     | validate_fixed_range             | 4          |
|        | io_uring/alloc_cache.h                              | io_alloc_cache_free              | 2          |
|        | drivers/net/ethernet/sun/sunvnet_common.c           | unlikely                         | 14         |
|        | include/linux/nospec.h                              | array_index_nospec               | 3          |
|        | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE                     | 3          |
|        | arch/arm64/include/asm/atomic.h                     | atomic64_add                     | 1          |
|        | io_uring/filetable.c                                | io_fixed_file_set                | 2          |
|        | drivers/gpu/drm/gma500/framebuffer.c                | IS_ERR                           | 7          |
|        | include/linux/lockdep.h                             | lockdep_assert_held              | 3          |
|        | arch/arc/include/asm/arcregs.h                      | min                              | 1          |
|        | include/linux/slab.h                                | kvmalloc                         | 1          |
|        | fs/btrfs/extent_io.h                                | folio_size                       | 1          |
|        | io_uring/rsrc.c                                     | io_vec_fill_kern_bvec            | 2          |
|        | io_uring/rsrc.c                                     | io_kern_bvec_size                | 2          |
|        | include/linux/build_bug.h                           | BUILD_BUG_ON                     | 1          |
|        | io_uring/rsrc.h                                     | io_vec_free                      | 3          |
|        | .vmlinux.export.c                                   | memcpy                           | 1          |
|        | io_uring/rsrc.c                                     | io_estimate_bvec_size            | 2          |
|        | io_uring/rsrc.c                                     | io_free_imu                      | 3          |
|        | io_uring/rsrc.h                                     | io_check_coalesce_buffer         | 2          |
|        | .vmlinux.export.c                                   | mutex_unlock                     | 2          |
|        | io_uring/filetable.c                                | io_reset_rsrc_node               | 2          |
|        | include/linux/kernel.h                              | u64_to_user_ptr                  | 9          |
|        | io_uring/cancel.c                                   | io_ring_submit_unlock            | 4          |
|        | drivers/usb/class/cdc-wdm.c                         | PTR_ERR                          | 7          |
|        | kernel/trace/trace_events.c                         | refcount_dec_and_test            | 1          |
|        | include/linux/bvec.h                                | for_each_mp_bvec                 | 1          |
|        | include/linux/slab.h                                | kvmalloc_array                   | 2          |
|        | include/linux/mutex.h                               | mutex_lock_nested                | 1          |
|        | io_uring/rsrc.h                                     | io_sqe_files_unregister          | 2          |
|        | io_uring/rsrc.h                                     | io_find_buf_node                 | 3          |
|        | io_uring/filetable.c                                | io_file_bitmap_clear             | 1          |
|        | arch/arm64/include/asm/atomic.h                     | atomic64_sub                     | 1          |
|        | io_uring/rsrc.c                                     | io_account_mem                   | 2          |
|        | io_uring/rsrc.h                                     | io_sqe_files_register            | 2          |
|        | block/bio-integrity.c                               | bvec_iter_advance                | 1          |
|        | Documentation/scheduler/sched-pelt.c                | max                              | 1          |
|        | .vmlinux.export.c                                   | kvfree                           | 4          |
|        | io_uring/filetable.h                                | io_free_file_tables              | 1          |
|        | include/linux/blk-mq.h                              | rq_for_each_bvec                 | 1          |
|        | include/linux/uio.h                                 | iovec_from_user                  | 3          |
|        | .vmlinux.export.c                                   | memset                           | 3          |
|        | .vmlinux.export.c                                   | iov_iter_advance                 | 3          |
|        | kernel/trace/trace_events.c                         | refcount_set                     | 2          |
|        | io_uring/advise.c                                   | io_req_set_res                   | 1          |
|        | arch/arm64/kernel/pi/relacheck.c                    | swap                             | 1          |
|        | include/linux/overflow.h                            | struct_size_t                    | 2          |
|        | io_uring/filetable.h                                | io_fixed_fd_install              | 1          |
|        | arch/sh/kernel/traps_32.c                           | copy_from_user                   | 11         |
|        | io_uring/rsrc.h                                     | io_sqe_buffers_unregister        | 2          |
|        | io_uring/io_uring.h                                 | io_is_compat                     | 1          |
|        | io_uring/rsrc.c                                     | io_sqe_buffer_register           | 4          |
|        | .vmlinux.export.c                                   | iov_iter_bvec                    | 3          |
|        | include/linux/mm.h                                  | folio_page_idx                   | 2          |
|        | io_uring/cancel.c                                   | io_slot_file                     | 1          |
|        | io_uring/memmap.h                                   | io_pin_pages                     | 1          |
|        | io_uring/rsrc.c                                     | headpage_already_acct            | 2          |
|        | io_uring/cancel.c                                   | io_ring_submit_lock              | 4          |
|        | io_uring/rsrc.c                                     | io_import_fixed                  | 2          |
|        | io_uring/io_uring.h                                 | io_post_aux_cqe                  | 1          |
|        | io_uring/rsrc.c                                     | io_files_update_with_index_alloc | 2          |
|        | .vmlinux.export.c                                   | kfree                            | 2          |
|        | io_uring/rsrc.c                                     | lock_two_rings                   | 2          |
|        | io_uring/cancel.c                                   | io_rsrc_node_lookup              | 2          |
|        | include/linux/blk-mq.h                              | rq_data_dir                      | 1          |
|        | .vmlinux.export.c                                   | mutex_lock                       | 1          |
|        | io_uring/filetable.c                                | io_file_table_set_alloc_range    | 2          |
|        | .vmlinux.export.c                                   | fget                             | 3          |
|        | include/linux/io_uring.h                            | io_is_uring_fops                 | 2          |
|        | arch/arm64/kvm/ptdump.c                             | release                          | 1          |
|        | arch/x86/virt/svm/sev.c                             | PageCompound                     | 3          |
|        | io_uring/register.h                                 | io_uring_register_get_file       | 1          |
|        | arch/powerpc/boot/types.h                           | min_t                            | 3          |
|        | io_uring/rsrc.c                                     | io_buffer_account_pin            | 2          |
|        | io_uring/alloc_cache.h                              | io_cache_alloc                   | 2          |
|        | io_uring/rsrc.h                                     | io_rsrc_data_free                | 4          |
|        | include/linux/io_uring/cmd.h                        | cmd_to_io_kiocb                  | 2          |
|        | arch/arc/mm/tlb.c                                   | folio_nr_pages                   | 1          |
|        | .vmlinux.export.c                                   | fput                             | 6          |
|        | io_uring/rsrc.h                                     | io_sqe_buffers_register          | 2          |
|        | include/linux/page-flags.h                          | page_folio                       | 3          |
|        | io_uring/rsrc.c                                     | io_vec_fill_bvec                 | 2          |
|        | io_uring/filetable.h                                | io_alloc_file_tables             | 1          |
|        | drivers/usb/class/cdc-wdm.c                         | READ_ONCE                        | 3          |
|        | drivers/gpu/drm/gma500/framebuffer.c                | ERR_PTR                          | 2          |
|        | .vmlinux.export.c                                   | memchr_inv                       | 1          |
|        | .vmlinux.export.c                                   | unpin_user_pages                 | 3          |
|        | io_uring/rsrc.c                                     | io_alloc_imu                     | 3          |
|        | io_uring/rsrc.c                                     | io_put_rsrc_node                 | 2          |
|        | io_uring/alloc_cache.c                              | io_alloc_cache_init              | 2          |
|        | fs/btrfs/extent_io.h                                | folio_shift                      | 1          |
|        | arch/powerpc/platforms/pseries/cmm.c                | atomic_long_read                 | 1          |
|        | io_uring/rsrc.h                                     | io_rsrc_node_alloc               | 6          |
|        | arch/um/drivers/ubd_kern.c                          | blk_rq_bytes                     | 1          |
|        | io_uring/rsrc.h                                     | io_buffer_validate               | 3          |
|        | arch/parisc/include/asm/processor.h                 | rlimit                           | 2          |
|        | io_uring/rsrc.c                                     | io_req_assign_buf_node           | 1          |
|        | io_uring/rsrc.c                                     | iov_kern_bvec_size               | 2          |
|        | kernel/trace/trace_events.c                         | refcount_inc                     | 1          |
|        | include/linux/overflow.h                            | check_add_overflow               | 7          |
|        | arch/um/drivers/ubd_kern.c                          | blk_rq_nr_phys_segments          | 1          |
|        | arch/s390/kvm/pci.c                                 | atomic_long_try_cmpxchg          | 1          |
|        | io_uring/rsrc.h                                     | io_vec_realloc                   | 3          |
|        | block/bio-integrity.c                               | bvec_set_page                    | 2          |
|        | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | kmalloc_array                    | 1          |
|        | .vmlinux.export.c                                   | unpin_user_page                  | 1          |
|        | io_uring/rsrc.c                                     | io_clone_buffers                 | 2          |
|        | io_uring/rsrc.h                                     | io_rsrc_data_alloc               | 3          |
|        | io_uring/rsrc.c                                     | io_buffer_unmap                  | 3          |
|        | include/linux/mm_types.h                            | compound_head                    | 4          |
|        | arch/arm/kernel/atags_compat.c                      | page_size                        | 1          |
|        | io_uring/advise.c                                   | req_set_fail                     | 1          |
|        | io_uring/alloc_cache.h                              | io_cache_free                    | 3          |
|        | io_uring/rsrc.c                                     | io_unaccount_mem                 | 2          |
|        | io_uring/rsrc.c                                     | io_coalesce_buffer               | 2          |
|        | arch/sh/kernel/traps_32.c                           | copy_to_user                     | 1          |

### rw.c
| Source | Library                                             | Function Utilized                | Times Used |
| ------ | --------------------------------------------------- | -------------------------------- | ---------- |
| rw.c   | arch/s390/hypfs/inode.c                             | write_iter                       | 2          |
|        | .vmlinux.export.c                                   | kfree                            | 1          |
|        | io_uring/rw.c                                       | io_import_vec                    | 2          |
|        | io_uring/rw.c                                       | io_prep_rw_pi                    | 2          |
|        | io_uring/alloc_cache.h                              | io_alloc_cache_put               | 1          |
|        | arch/alpha/kernel/core_cia.c                        | read                             | 2          |
|        | include/linux/pagemap.h                             | wake_page_match                  | 1          |
|        | .vmlinux.export.c                                   | iov_iter_advance                 | 2          |
|        | io_uring/io_uring.h                                 | io_req_task_complete             | 1          |
|        | drivers/hv/mshv_eventfd.c                           | vfs_poll                         | 1          |
|        | io_uring/rw.c                                       | io_rw_prep_reg_vec               | 3          |
|        | io_uring/rw.c                                       | io_req_end_write                 | 5          |
|        | io_uring/rw.c                                       | io_kiocb_ppos                    | 2          |
|        | io_uring/io_uring.h                                 | io_uring_alloc_async_data        | 1          |
|        | io_uring/filetable.h                                | io_file_get_flags                | 1          |
|        | io_uring/rw.c                                       | io_uring_classic_poll            | 3          |
|        | include/linux/ioprio.h                              | ioprio_check_cap                 | 1          |
|        | include/linux/kernel.h                              | u64_to_user_ptr                  | 7          |
|        | include/asm-generic/barrier.h                       | smp_store_release                | 1          |
|        | io_uring/rw.c                                       | io_rw_init_file                  | 3          |
|        | drivers/pps/generators/pps_gen_parport.c            | hrtimer_set_expires              | 1          |
|        | io_uring/rw.c                                       | io_meta_restore                  | 4          |
|        | io_uring/io_uring.c                                 | io_put_kbuf                      | 5          |
|        | io_uring/rsrc.h                                     | io_import_reg_buf                | 1          |
|        | io_uring/kbuf.h                                     | io_buffer_select                 | 1          |
|        | block/bio.c                                         | iov_iter_is_bvec                 | 2          |
|        | io_uring/io_uring.h                                 | req_has_async_data               | 1          |
|        | kernel/time/hrtimer.c                               | destroy_hrtimer_on_stack         | 1          |
|        | fs/btrfs/ioctl.c                                    | fsnotify_access                  | 1          |
|        | include/linux/io_uring/cmd.h                        | cmd_to_io_kiocb                  | 3          |
|        | io_uring/slist.h                                    | wq_list_empty                    | 1          |
|        | .vmlinux.export.c                                   | io_schedule                      | 1          |
|        | io_uring/slist.h                                    | wq_list_for_each_resume          | 1          |
|        | include/linux/lockdep.h                             | lockdep_assert_held              | 1          |
|        | drivers/usb/class/cdc-wdm.c                         | READ_ONCE                        | 10         |
|        | .vmlinux.export.c                                   | hrtimer_cancel                   | 1          |
|        | drivers/infiniband/hw/bnxt_re/ib_verbs.c            | INIT_LIST_HEAD                   | 1          |
|        | io_uring/io_uring.c                                 | io_kbuf_recycle                  | 2          |
|        | include/linux/blkdev.h                              | DEFINE_IO_COMP_BATCH             | 1          |
|        | io_uring/rw.c                                       | io_complete_rw_iopoll            | 4          |
|        | io_uring/io_uring.c                                 | io_file_can_poll                 | 4          |
|        | io_uring/rw.c                                       | io_iov_compat_buffer_select_prep | 2          |
|        | io_uring/rw.c                                       | io_rw_import_reg_vec             | 3          |
|        | include/uapi/linux/stat.h                           | S_ISREG                          | 1          |
|        | io_uring/advise.c                                   | req_set_fail                     | 2          |
|        | .vmlinux.export.c                                   | import_ubuf                      | 2          |
|        | block/fops.c                                        | iopoll                           | 1          |
|        | io_uring/io-wq.c                                    | wq_list_cut                      | 1          |
|        | include/linux/uio.h                                 | iter_iov_addr                    | 1          |
|        | io_uring/rw.c                                       | io_file_supports_nowait          | 3          |
|        | include/linux/fs.h                                  | dio_complete                     | 1          |
|        | include/linux/uio.h                                 | iov_iter_restore                 | 5          |
|        | io_uring/net.c                                      | io_vec_reset_iovec               | 1          |
|        | arch/powerpc/platforms/cell/spu_base.c              | ktime_get_ns                     | 2          |
|        | io_uring/rw.c                                       | io_rw_done                       | 2          |
|        | io_uring/advise.c                                   | io_req_set_res                   | 5          |
|        | fs/aio.c                                            | kiocb_start_write                | 1          |
|        | include/linux/io_uring_types.h                      | io_kiocb_to_cmd                  | 22         |
|        | block/blk-core.c                                    | get_current_ioprio               | 1          |
|        | io_uring/rw.c                                       | io_uring_hybrid_poll             | 2          |
|        | io_uring/cancel.c                                   | io_wq_current_is_worker          | 1          |
|        | io_uring/io_uring.h                                 | io_is_compat                     | 2          |
|        | io_uring/slist.h                                    | wq_list_for_each                 | 1          |
|        | .vmlinux.export.c                                   | complete                         | 1          |
|        | include/linux/uio.h                                 | iter_iov_len                     | 1          |
|        | arch/alpha/kernel/core_cia.c                        | write                            | 2          |
|        | io_uring/rw.c                                       | io_iter_do_read                  | 3          |
|        | arch/alpha/kernel/srm_env.c                         | file_inode                       | 3          |
|        | io_uring/rw.c                                       | io_complete_rw                   | 4          |
|        | drivers/usb/gadget/function/f_fs.c                  | iter_is_ubuf                     | 1          |
|        | fs/btrfs/super.c                                    | sb_start_write_trylock           | 1          |
|        | io_uring/rsrc.h                                     | io_import_reg_vec                | 1          |
|        | arch/mips/kvm/emulate.c                             | ktime_set                        | 1          |
|        | include/linux/uio.h                                 | iov_iter_save_state              | 6          |
|        | io_uring/rw.c                                       | io_rw_recycle                    | 3          |
|        | io_uring/io_uring.h                                 | io_req_task_queue                | 1          |
|        | io_uring/rw.c                                       | io_prep_rwv                      | 3          |
|        | arch/x86/kvm/kvm_emulate.h                          | io_read                          | 3          |
|        | arch/arm/probes/kprobes/opt-arm.c                   | list_del_init                    | 1          |
|        | fs/aio.c                                            | kiocb_end_write                  | 1          |
|        | io_uring/rw.c                                       | io_import_rw_buffer              | 3          |
|        | io_uring/rw.c                                       | io_prep_rw                       | 4          |
|        | include/linux/sched.h                               | set_current_state                | 1          |
|        | io_uring/rw.c                                       | kiocb_done                       | 3          |
|        | .vmlinux.export.c                                   | hrtimer_sleeper_start_expires    | 1          |
|        | .vmlinux.export.c                                   | rw_verify_area                   | 2          |
|        | io_uring/rw.c                                       | io_fixup_rw_res                  | 5          |
|        | io_uring/rw.c                                       | io_rw_should_reissue             | 3          |
|        | drivers/accel/habanalabs/common/hw_queue.c          | container_of                     | 5          |
|        | drivers/md/md.c                                     | percpu_ref_is_dying              | 1          |
|        | kernel/time/hrtimer.c                               | hrtimer_setup_sleeper_on_stack   | 1          |
|        | drivers/media/i2c/adv748x/adv748x.h                 | io_write                         | 2          |
|        | arch/sh/kernel/traps_32.c                           | copy_from_user                   | 3          |
|        | io_uring/rw.c                                       | trace_io_uring_short_write       | 1          |
|        | io_uring/io_uring.h                                 | io_req_post_cqe                  | 1          |
|        | io_uring/kbuf.h                                     | io_do_buffer_select              | 3          |
|        | io_uring/rw.c                                       | io_kiocb_update_pos              | 3          |
|        | fs/aio.c                                            | kiocb_set_rw_flags               | 1          |
|        | io_uring/rw.c                                       | io_iov_buffer_select_prep        | 2          |
|        | include/uapi/linux/stat.h                           | S_ISBLK                          | 2          |
|        | io_uring/poll.h                                     | io_poll_multishot_retry          | 1          |
|        | io_uring/rw.c                                       | io_hybrid_iopoll_delay           | 2          |
|        | drivers/net/ethernet/sun/sunvnet_common.c           | unlikely                         | 28         |
|        | include/linux/compiler.h                            | likely                           | 2          |
|        | arch/s390/hypfs/inode.c                             | read_iter                        | 2          |
|        | io_uring/rw.c                                       | loop_rw_iter                     | 3          |
|        | io_uring/rw.c                                       | io_rw_should_retry               | 2          |
|        | io_uring/net.c                                      | io_alloc_cache_vec_kasan         | 1          |
|        | io_uring/rsrc.h                                     | io_prep_reg_iovec                | 1          |
|        | io_uring/rw.c                                       | io_meta_save_state               | 2          |
|        | io_uring/rw.c                                       | io_rw_alloc_async                | 2          |
|        | block/blk-core.c                                    | rq_list_empty                    | 2          |
|        | include/asm-generic/barrier.h                       | smp_load_acquire                 | 1          |
|        | io_uring/rsrc.h                                     | io_vec_free                      | 2          |
|        | io_uring/rw.c                                       | io_req_io_end                    | 3          |
|        | io_uring/rw.c                                       | io_init_rw_fixed                 | 3          |
|        | io_uring/rw.c                                       | need_complete_io                 | 3          |
|        | io_uring/rw.c                                       | io_kiocb_start_write             | 2          |
|        | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE                     | 1          |
|        | io_uring/rw.c                                       | io_req_rw_cleanup                | 5          |
|        | arch/s390/hypfs/inode.c                             | iov_iter_count                   | 7          |
|        | io_uring/rw.c                                       | io_rw_do_import                  | 2          |
|        | drivers/nvme/host/core.c                            | uring_cmd_iopoll                 | 1          |
|        | fs/btrfs/ioctl.c                                    | fsnotify_modify                  | 1          |

### splice.c
| Source   | Library                                             | Function Utilized     | Times Used |
| -------- | --------------------------------------------------- | --------------------- | ---------- |
| splice.c | include/linux/io_uring_types.h                      | io_kiocb_to_cmd       | 6          |
|          | io_uring/cancel.c                                   | io_rsrc_node_lookup   | 1          |
|          | .vmlinux.export.c                                   | fput                  | 2          |
|          | io_uring/advise.c                                   | io_req_set_res        | 2          |
|          | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE          | 2          |
|          | io_uring/cancel.c                                   | io_ring_submit_lock   | 1          |
|          | io_uring/cancel.c                                   | io_slot_file          | 1          |
|          | drivers/usb/class/cdc-wdm.c                         | READ_ONCE             | 7          |
|          | io_uring/io_uring.h                                 | io_file_get_normal    | 1          |
|          | drivers/net/ethernet/sun/sunvnet_common.c           | unlikely              | 1          |
|          | include/linux/splice.h                              | do_tee                | 1          |
|          | io_uring/splice.c                                   | io_splice_get_file    | 3          |
|          | io_uring/advise.c                                   | req_set_fail          | 2          |
|          | io_uring/rsrc.c                                     | io_put_rsrc_node      | 1          |
|          | io_uring/cancel.c                                   | io_ring_submit_unlock | 1          |
|          | fs/splice.c                                         | do_splice             | 1          |

### sqpoll.c
| Source   | Library                | Function Utilized           | Times Used |
| -------- | ---------------------- | --------------------------- | ---------- |
| sqpoll.c | io_uring/io-wq.c       | set_bit                     | 3          |
|          | io_uring/slist.h       | wq_list_empty               | 4          |
|          | io_uring/io_uring.c    | llist_empty                 | 1          |
|          | io_uring/io_uring.h    | percpu_ref_is_dying         | 1          |
|          | io_uring/sqpoll.c      | cpu_online                  | 1          |
|          | io_uring/io-wq.c       | kzalloc                     | 1          |
|          | io_uring/io-wq.c       | get_task_struct             | 1          |
|          | io_uring/sqpoll.c      | wait_event                  | 1          |
|          | io_uring/io-wq.c       | INIT_LIST_HEAD              | 1          |
|          | io_uring/fdinfo.c      | getrusage                   | 2          |
|          | io_uring/msg_ring.c    | fd_file                     | 3          |
|          | io_uring/sqpoll.c      | atomic_dec_return           | 1          |
|          | io_uring/cancel.c      | mutex_unlock                | 8          |
|          | io_uring/io_uring.c    | audit_uring_entry           | 1          |
|          | io_uring/io_uring.c    | current_cred                | 1          |
|          | io_uring/cancel.c      | unlikely                    | 1          |
|          | io_uring/io-wq.c       | clear_bit                   | 1          |
|          | io_uring/cancel.c      | DEFINE_WAIT                 | 2          |
|          | io_uring/sqpoll.h      | io_sq_thread_finish         | 1          |
|          | io_uring/sqpoll.h      | io_sq_thread_park           | 3          |
|          | io_uring/cancel.c      | finish_wait                 | 2          |
|          | io_uring/filetable.c   | io_is_uring_fops            | 2          |
|          | io_uring/fdinfo.c      | task_work_pending           | 1          |
|          | io_uring/io_uring.c    | override_creds              | 1          |
|          | io_uring/io_uring.c    | max                         | 1          |
|          | io_uring/sqpoll.h      | io_put_sq_data              | 1          |
|          | io_uring/io_uring.h    | io_handle_tw_list           | 1          |
|          | io_uring/sqpoll.c      | security_uring_sqpoll       | 1          |
|          | io_uring/io-wq.c       | cond_resched                | 1          |
|          | io_uring/cancel.c      | prepare_to_wait             | 2          |
|          | io_uring/sqpoll.h      | io_sq_thread_stop           | 1          |
|          | io_uring/io-wq.c       | msecs_to_jiffies            | 1          |
|          | io_uring/io_uring.c    | init_waitqueue_head         | 1          |
|          | io_uring/io-wq.c       | __releases                  | 1          |
|          | io_uring/notif.c       | complete                    | 2          |
|          | io_uring/io_uring.c    | mutex_init                  | 1          |
|          | io_uring/io_uring.h    | io_submit_sqes              | 1          |
|          | io_uring/io-wq.h       | io_wq_cpu_affinity          | 1          |
|          | io_uring/refs.h        | data_race                   | 1          |
|          | io_uring/sqpoll.c      | io_sqd_events_pending       | 2          |
|          | io_uring/io-wq.c       | atomic_read                 | 2          |
|          | io_uring/sqpoll.c      | smp_mb__after_atomic        | 1          |
|          | io_uring/io-wq.c       | wait_for_completion         | 1          |
|          | io_uring/io-wq.c       | free_cpumask_var            | 2          |
|          | io_uring/io-wq.c       | do_exit                     | 1          |
|          | io_uring/io-wq.c       | wake_up_new_task            | 1          |
|          | io_uring/io-wq.c       | raw_smp_processor_id        | 4          |
|          | io_uring/io-wq.c       | wake_up_process             | 2          |
|          | io_uring/advise.c      | WARN_ON_ONCE                | 5          |
|          | io_uring/cancel.c      | mutex_lock                  | 8          |
|          | io_uring/io-wq.c       | get_signal                  | 1          |
|          | io_uring/io-wq.c       | __acquires                  | 1          |
|          | io_uring/sqpoll.c      | io_sq_update_worktime       | 1          |
|          | io_uring/io_uring.c    | revert_creds                | 1          |
|          | io_uring/alloc_cache.h | kfree                       | 1          |
|          | io_uring/sqpoll.c      | io_get_sq_data              | 1          |
|          | io_uring/io-wq.c       | io_run_task_work            | 1          |
|          | io_uring/io-wq.c       | likely                      | 1          |
|          | io_uring/io_uring.h    | task_work_run               | 1          |
|          | io_uring/io-wq.c       | ERR_PTR                     | 5          |
|          | io_uring/io_uring.h    | io_uring_cancel_generic     | 1          |
|          | io_uring/io-wq.c       | init_completion             | 1          |
|          | io_uring/eventfd.c     | refcount_dec_and_test       | 1          |
|          | io_uring/io_uring.c    | atomic_andnot               | 1          |
|          | io_uring/io-wq.c       | put_task_struct             | 2          |
|          | io_uring/io-wq.c       | atomic_inc                  | 1          |
|          | io_uring/io-wq.c       | alloc_cpumask_var           | 1          |
|          | io_uring/io_uring.c    | io_sqring_entries           | 2          |
|          | io_uring/sqpoll.c      | io_sq_tw                    | 2          |
|          | io_uring/sqpoll.c      | cpumask_of                  | 1          |
|          | io_uring/sqpoll.h      | io_sq_thread_unpark         | 3          |
|          | io_uring/sqpoll.c      | io_sqd_update_thread_idle   | 2          |
|          | io_uring/filetable.h   | test_bit                    | 3          |
|          | io_uring/napi.h        | io_napi_sqpoll_busy_poll    | 1          |
|          | io_uring/eventfd.c     | atomic_set                  | 1          |
|          | io_uring/io_uring.h    | io_uring_alloc_task_context | 1          |
|          | io_uring/kbuf.c        | list_add                    | 1          |
|          | io_uring/sqpoll.c      | io_attach_sq_data           | 1          |
|          | io_uring/msg_ring.c    | fd_empty                    | 2          |
|          | io_uring/io-wq.c       | list_del_init               | 1          |
|          | io_uring/io-wq.c       | snprintf                    | 1          |
|          | io_uring/io-wq.c       | wake_up                     | 2          |
|          | io_uring/io-wq.c       | cpuset_cpus_allowed         | 1          |
|          | io_uring/sqpoll.c      | __io_sq_thread              | 1          |
|          | io_uring/io-wq.c       | signal_pending              | 4          |
|          | io_uring/msg_ring.c    | CLASS                       | 2          |
|          | io_uring/eventfd.c     | PTR_ERR                     | 3          |
|          | io_uring/eventfd.c     | refcount_set                | 1          |
|          | io_uring/io_uring.c    | io_sqring_full              | 2          |
|          | io_uring/cancel.c      | list_for_each_entry         | 6          |
|          | io_uring/eventfd.c     | IS_ERR                      | 3          |
|          | io_uring/io_uring.c    | get_current_cred            | 1          |
|          | io_uring/io-wq.c       | wq_has_sleeper              | 1          |
|          | io_uring/io-wq.c       | atomic_or                   | 2          |
|          | io_uring/io-wq.c       | cpumask_test_cpu            | 1          |
|          | io_uring/sqpoll.c      | io_sqd_handle_event         | 1          |
|          | io_uring/napi.h        | io_napi                     | 1          |
|          | io_uring/napi.c        | list_is_singular            | 1          |
|          | io_uring/io_uring.h    | io_do_iopoll                | 1          |
|          | io_uring/sqpoll.c      | io_sq_tw_pending            | 1          |
|          | io_uring/io-wq.c       | refcount_inc                | 1          |
|          | io_uring/advise.c      | READ_ONCE                   | 1          |
|          | io_uring/io-wq.c       | create_io_thread            | 1          |
|          | io_uring/io_uring.c    | schedule                    | 2          |
|          | io_uring/io_uring.c    | need_resched                | 1          |
|          | io_uring/io-wq.c       | set_task_comm               | 1          |
|          | io_uring/io_uring.h    | tctx_task_work_run          | 1          |
|          | io_uring/io-wq.c       | set_cpus_allowed_ptr        | 2          |
|          | io_uring/io_uring.c    | audit_uring_exit            | 1          |
|          | io_uring/io_uring.c    | time_after                  | 1          |

### statx.c
| Source  | Library            | Function Utilized | Times Used |
| ------- | ------------------ | ----------------- | ---------- |
| statx.c | io_uring/statx.c   | do_statx          | 1          |
|         | io_uring/advise.c  | io_req_set_res    | 1          |
|         | io_uring/eventfd.c | PTR_ERR           | 1          |
|         | io_uring/eventfd.c | IS_ERR            | 1          |
|         | io_uring/advise.c  | io_kiocb_to_cmd   | 3          |
|         | io_uring/fs.c      | getname_uflags    | 1          |
|         | io_uring/advise.c  | WARN_ON_ONCE      | 1          |
|         | io_uring/advise.c  | READ_ONCE         | 5          |
|         | io_uring/fs.c      | putname           | 1          |
|         | io_uring/epoll.c   | u64_to_user_ptr   | 2          |

### sync.c
| Source | Library           | Function Utilized | Times Used |
| ------ | ----------------- | ----------------- | ---------- |
| sync.c | io_uring/sync.c   | vfs_fallocate     | 1          |
|        | io_uring/advise.c | WARN_ON_ONCE      | 3          |
|        | io_uring/advise.c | io_req_set_res    | 3          |
|        | io_uring/sync.c   | sync_file_range   | 1          |
|        | io_uring/advise.c | READ_ONCE         | 9          |
|        | io_uring/sync.c   | vfs_fsync_range   | 1          |
|        | io_uring/rw.c     | fsnotify_modify   | 1          |
|        | io_uring/cancel.c | unlikely          | 3          |
|        | io_uring/advise.c | io_kiocb_to_cmd   | 6          |

### tctx.c
| Source | Library                | Function Utilized           | Times Used |
| ------ | ---------------------- | --------------------------- | ---------- |
| tctx.c | io_uring/alloc_cache.h | kfree                       | 5          |
|        | io_uring/cancel.c      | mutex_lock                  | 4          |
|        | io_uring/tctx.c        | io_ring_add_registered_fd   | 1          |
|        | io_uring/io_uring.c    | xa_load                     | 1          |
|        | io_uring/kbuf.c        | xa_store                    | 1          |
|        | io_uring/io-wq.h       | io_wq_put_and_exit          | 1          |
|        | io_uring/io-wq.h       | io_wq_create                | 1          |
|        | io_uring/io-wq.c       | kzalloc                     | 2          |
|        | io_uring/cancel.c      | copy_from_user              | 2          |
|        | io_uring/eventfd.c     | refcount_set                | 1          |
|        | io_uring/io_uring.c    | init_waitqueue_head         | 2          |
|        | io_uring/tctx.h        | io_uring_del_tctx_node      | 1          |
|        | io_uring/advise.c      | WARN_ON_ONCE                | 5          |
|        | io_uring/io_uring.h    | io_ring_add_registered_file | 1          |
|        | io_uring/fdinfo.c      | xa_for_each                 | 2          |
|        | io_uring/cancel.c      | mutex_unlock                | 5          |
|        | io_uring/io_uring.c    | list_del                    | 1          |
|        | io_uring/kbuf.c        | list_add                    | 1          |
|        | io_uring/io_uring.c    | array_index_nospec          | 2          |
|        | io_uring/io_uring.c    | xa_init                     | 1          |
|        | io_uring/fdinfo.c      | min                         | 1          |
|        | io_uring/eventfd.c     | PTR_ERR                     | 1          |
|        | io_uring/io-wq.c       | list_empty                  | 1          |
|        | io_uring/tctx.c        | percpu_counter_init         | 1          |
|        | io_uring/filetable.c   | io_is_uring_fops            | 1          |
|        | io_uring/cancel.c      | fput                        | 5          |
|        | io_uring/cancel.c      | fget                        | 1          |
|        | io_uring/kbuf.c        | xa_erase                    | 1          |
|        | io_uring/eventfd.c     | IS_ERR                      | 1          |
|        | io_uring/io_uring.c    | copy_to_user                | 1          |
|        | io_uring/tctx.c        | num_online_cpus             | 1          |
|        | io_uring/io-wq.c       | init_task_work              | 1          |
|        | io_uring/io-wq.c       | ERR_PTR                     | 1          |
|        | io_uring/io_uring.c    | init_llist_head             | 1          |
|        | io_uring/tctx.h        | __io_uring_add_tctx_node    | 2          |
|        | io_uring/kbuf.c        | xa_err                      | 1          |
|        | io_uring/cancel.c      | unlikely                    | 4          |
|        | io_uring/alloc_cache.c | kmalloc                     | 1          |
|        | io_uring/io-wq.h       | io_wq_max_workers           | 1          |
|        | io_uring/tctx.c        | percpu_counter_destroy      | 2          |
|        | io_uring/eventfd.c     | atomic_set                  | 2          |
|        | io_uring/tctx.c        | io_init_wq_offload          | 1          |
|        | io_uring/io-wq.c       | cond_resched                | 1          |
|        | io_uring/io_uring.h    | io_uring_alloc_task_context | 1          |

### timeout.c
| Source    | Library             | Function Utilized          | Times Used |
| --------- | ------------------- | -------------------------- | ---------- |
| timeout.c | io_uring/timeout.c  | list_for_each_prev         | 1          |
|           | io_uring/timeout.c  | raw_spin_unlock_irqrestore | 2          |
|           | io_uring/futex.c    | io_tw_lock                 | 1          |
|           | io_uring/refs.h     | req_ref_inc_not_zero       | 1          |
|           | io_uring/cancel.c   | unlikely                   | 3          |
|           | io_uring/io_uring.h | io_queue_next              | 1          |
|           | io_uring/cancel.c   | __must_hold                | 10         |
|           | io_uring/io-wq.c    | list_del_init              | 3          |
|           | io_uring/cancel.c   | timespec64_to_ktime        | 5          |
|           | io_uring/timeout.c  | __io_timeout_prep          | 2          |
|           | io_uring/timeout.c  | io_match_task              | 1          |
|           | io_uring/io-wq.c    | ERR_PTR                    | 2          |
|           | io_uring/io_uring.c | req_ref_put_and_test       | 1          |
|           | io_uring/timeout.c  | list_for_each_entry_safe   | 2          |
|           | io_uring/advise.c   | READ_ONCE                  | 4          |
|           | io_uring/eventfd.c  | PTR_ERR                    | 2          |
|           | io_uring/io-wq.c    | INIT_LIST_HEAD             | 1          |
|           | io_uring/timeout.c  | hweight32                  | 2          |
|           | io_uring/eventfd.c  | atomic_set                 | 2          |
|           | io_uring/epoll.c    | u64_to_user_ptr            | 2          |
|           | io_uring/eventfd.c  | IS_ERR                     | 2          |
|           | io_uring/timeout.c  | list_move_tail             | 1          |
|           | io_uring/timeout.c  | io_flush_killed_timeouts   | 2          |
|           | io_uring/io_uring.h | io_for_each_link           | 1          |
|           | io_uring/refs.h     | data_race                  | 1          |
|           | io_uring/io_uring.h | io_uring_alloc_async_data  | 1          |
|           | io_uring/io_uring.h | req_has_async_data         | 1          |
|           | io_uring/io-wq.c    | atomic_read                | 4          |
|           | io_uring/timeout.c  | io_linked_timeout_update   | 1          |
|           | io_uring/timeout.c  | hrtimer_start              | 5          |
|           | io_uring/timeout.c  | io_translate_timeout_mode  | 2          |
|           | io_uring/timeout.c  | io_timeout_finish          | 1          |
|           | io_uring/io_uring.h | io_req_queue_tw_complete   | 3          |
|           | io_uring/io_uring.h | io_req_task_queue_fail     | 1          |
|           | io_uring/timeout.c  | io_kill_timeout            | 2          |
|           | io_uring/timeout.c  | raw_spin_lock_irqsave      | 2          |
|           | io_uring/io_uring.c | get_timespec64             | 2          |
|           | io_uring/timeout.h  | io_timeout_cancel          | 1          |
|           | io_uring/io_uring.h | io_free_req                | 1          |
|           | io_uring/msg_ring.c | cmd_to_io_kiocb            | 6          |
|           | io_uring/advise.c   | io_req_set_res             | 5          |
|           | io_uring/cancel.c   | spin_unlock                | 2          |
|           | io_uring/io_uring.h | io_req_post_cqe            | 1          |
|           | io_uring/cancel.h   | io_cancel_req_match        | 1          |
|           | io_uring/io_uring.c | raw_spin_unlock_irq        | 6          |
|           | io_uring/io_uring.c | list_add_tail              | 2          |
|           | io_uring/io-wq.c    | list_empty                 | 2          |
|           | io_uring/cancel.c   | spin_lock                  | 2          |
|           | io_uring/timeout.c  | io_timeout_extract         | 2          |
|           | io_uring/timeout.c  | io_is_timeout_noseq        | 3          |
|           | io_uring/timeout.c  | io_disarm_linked_timeout   | 1          |
|           | io_uring/timeout.c  | io_remove_next_linked      | 3          |
|           | io_uring/io_uring.c | LIST_HEAD                  | 2          |
|           | io_uring/io_uring.c | io_should_terminate_tw     | 1          |
|           | io_uring/advise.c   | req_set_fail               | 3          |
|           | io_uring/cancel.c   | list_for_each_entry        | 2          |
|           | io_uring/advise.c   | io_kiocb_to_cmd            | 14         |
|           | io_uring/futex.c    | io_req_task_work_add       | 3          |
|           | io_uring/timeout.c  | io_timeout_get_clock       | 4          |
|           | io_uring/kbuf.c     | list_add                   | 2          |
|           | io_uring/timeout.c  | trace_io_uring_fail_link   | 1          |
|           | io_uring/io_uring.h | io_req_task_complete       | 4          |
|           | io_uring/cancel.c   | container_of               | 2          |
|           | io_uring/timeout.c  | io_fail_links              | 1          |
|           | io_uring/io_uring.c | list_del                   | 2          |
|           | io_uring/advise.c   | WARN_ON_ONCE               | 2          |
|           | io_uring/timeout.c  | io_put_req                 | 2          |
|           | io_uring/cancel.h   | io_try_cancel              | 1          |
|           | io_uring/io_uring.c | list_first_entry           | 1          |
|           | io_uring/timeout.c  | io_timeout_update          | 1          |
|           | io_uring/io_uring.c | raw_spin_lock_irq          | 8          |
|           | io_uring/timeout.c  | list_entry                 | 1          |
|           | io_uring/timeout.c  | hrtimer_try_to_cancel      | 4          |
|           | io_uring/timeout.c  | hrtimer_setup              | 4          |

### truncate.c
| Source     | Library             | Function Utilized | Times Used |
| ---------- | ------------------- | ----------------- | ---------- |
| truncate.c | io_uring/advise.c   | io_req_set_res    | 1          |
|            | io_uring/truncate.c | do_ftruncate      | 1          |
|            | io_uring/advise.c   | READ_ONCE         | 1          |
|            | io_uring/advise.c   | WARN_ON_ONCE      | 1          |
|            | io_uring/advise.c   | io_kiocb_to_cmd   | 2          |

### uring_cmd.c
| Source      | Library                | Function Utilized           | Times Used |
| ----------- | ---------------------- | --------------------------- | ---------- |
| uring_cmd.c | io_uring/uring_cmd.c   | KERNEL_SOCKPTR              | 1          |
|             | io_uring/uring_cmd.c   | task_work_cb                | 1          |
|             | io_uring/io_uring.h    | io_uring_alloc_async_data   | 1          |
|             | io_uring/uring_cmd.c   | io_req_uring_cleanup        | 3          |
|             | io_uring/advise.c      | req_set_fail                | 2          |
|             | io_uring/futex.c       | io_req_task_work_add        | 1          |
|             | io_uring/uring_cmd.c   | uring_cmd                   | 2          |
|             | io_uring/alloc_cache.h | io_alloc_cache_put          | 1          |
|             | io_uring/alloc_cache.h | kfree                       | 2          |
|             | io_uring/rsrc.h        | io_vec_free                 | 2          |
|             | io_uring/uring_cmd.c   | security_uring_cmd          | 1          |
|             | io_uring/io_uring.c    | io_should_terminate_tw      | 1          |
|             | io_uring/advise.c      | READ_ONCE                   | 12         |
|             | io_uring/rsrc.h        | io_import_reg_vec           | 1          |
|             | io_uring/epoll.c       | u64_to_user_ptr             | 2          |
|             | io_uring/advise.c      | WARN_ON_ONCE                | 1          |
|             | io_uring/io_uring.c    | io_req_complete_defer       | 1          |
|             | io_uring/net.c         | io_alloc_cache_vec_kasan    | 1          |
|             | io_uring/io_uring.c    | io_submit_flush_completions | 1          |
|             | io_uring/cancel.c      | io_ring_submit_lock         | 2          |
|             | io_uring/futex.c       | hlist_add_head              | 1          |
|             | io_uring/uring_cmd.c   | do_sock_getsockopt          | 1          |
|             | io_uring/io_uring.h    | io_req_queue_iowq           | 1          |
|             | io_uring/uring_cmd.c   | io_uring_cmd_getsockopt     | 1          |
|             | io_uring/io_uring.c    | offsetof                    | 1          |
|             | io_uring/uring_cmd.c   | ioctl                       | 2          |
|             | io_uring/uring_cmd.c   | do_sock_setsockopt          | 1          |
|             | io_uring/uring_cmd.c   | io_req_set_cqe32_extra      | 1          |
|             | io_uring/uring_cmd.c   | io_uring_cmd_del_cancelable | 1          |
|             | io_uring/uring_cmd.c   | USER_SOCKPTR                | 2          |
|             | io_uring/io_uring.c    | smp_store_release           | 1          |
|             | io_uring/uring_cmd.c   | io_uring_cmd_prep_setup     | 1          |
|             | io_uring/io_uring.c    | memcpy                      | 1          |
|             | io_uring/cancel.c      | hlist_for_each_entry_safe   | 1          |
|             | io_uring/msg_ring.c    | cmd_to_io_kiocb             | 7          |
|             | io_uring/cancel.c      | io_ring_submit_unlock       | 2          |
|             | io_uring/io_uring.h    | uring_sqe_size              | 1          |
|             | io_uring/advise.c      | io_req_set_res              | 2          |
|             | io_uring/uring_cmd.c   | hlist_del                   | 1          |
|             | io_uring/rsrc.h        | io_import_reg_buf           | 1          |
|             | io_uring/io_uring.h    | io_is_compat                | 1          |
|             | io_uring/uring_cmd.c   | io_uring_cmd_setsockopt     | 1          |
|             | io_uring/io-wq.c       | BUILD_BUG_ON                | 1          |
|             | io_uring/rsrc.h        | io_prep_reg_iovec           | 1          |
|             | io_uring/advise.c      | io_kiocb_to_cmd             | 6          |
|             | io_uring/io_uring.h    | __io_req_task_work_add      | 1          |
|             | io_uring/cancel.c      | lockdep_assert_held         | 1          |

### waitid.c
| Source   | Library                | Function Utilized         | Times Used |
| -------- | ---------------------- | ------------------------- | ---------- |
| waitid.c | io_uring/cancel.c      | io_ring_submit_lock       | 1          |
|          | io_uring/advise.c      | READ_ONCE                 | 4          |
|          | io_uring/waitid.c      | kernel_waitid_prepare     | 1          |
|          | io_uring/eventfd.c     | BIT                       | 1          |
|          | io_uring/poll.c        | atomic_fetch_inc          | 2          |
|          | io_uring/waitid.c      | __do_wait                 | 3          |
|          | io_uring/io_uring.h    | io_is_compat              | 1          |
|          | io_uring/advise.c      | req_set_fail              | 2          |
|          | io_uring/futex.c       | io_req_task_work_add      | 2          |
|          | io_uring/advise.c      | io_kiocb_to_cmd           | 8          |
|          | io_uring/eventfd.c     | atomic_set                | 1          |
|          | io_uring/futex.c       | hlist_add_head            | 1          |
|          | io_uring/io-wq.c       | list_del_init             | 2          |
|          | io_uring/advise.c      | WARN_ON_ONCE              | 1          |
|          | io_uring/cancel.c      | hlist_del_init            | 2          |
|          | io_uring/io-wq.c       | spin_lock_irq             | 1          |
|          | io_uring/waitid.c      | user_write_access_begin   | 2          |
|          | io_uring/io_uring.h    | io_req_queue_tw_complete  | 1          |
|          | io_uring/waitid.c      | io_waitid_finish          | 2          |
|          | io_uring/cancel.c      | io_ring_submit_unlock     | 3          |
|          | io_uring/poll.c        | atomic_sub_return         | 1          |
|          | io_uring/waitid.c      | user_write_access_end     | 2          |
|          | io_uring/waitid.c      | io_waitid_drop_issue_ref  | 2          |
|          | io_uring/alloc_cache.h | kfree                     | 1          |
|          | io_uring/cancel.c      | io_cancel_remove          | 1          |
|          | io_uring/cancel.c      | container_of              | 2          |
|          | io_uring/epoll.c       | u64_to_user_ptr           | 1          |
|          | io_uring/waitid.c      | remove_wait_queue         | 3          |
|          | io_uring/waitid.c      | pid_child_should_wake     | 1          |
|          | io_uring/waitid.c      | io_waitid_complete        | 2          |
|          | io_uring/waitid.c      | put_pid                   | 1          |
|          | io_uring/cancel.c      | lockdep_assert_held       | 1          |
|          | io_uring/io-wq.c       | atomic_read               | 2          |
|          | io_uring/io-wq.c       | atomic_or                 | 1          |
|          | io_uring/waitid.c      | io_waitid_copy_si         | 1          |
|          | io_uring/waitid.c      | io_waitid_free            | 1          |
|          | io_uring/io_uring.h    | io_uring_alloc_async_data | 1          |
|          | io_uring/waitid.c      | io_waitid_compat_copy_si  | 1          |
|          | io_uring/waitid.c      | unsafe_put_user           | 12         |
|          | io_uring/futex.c       | io_tw_lock                | 1          |
|          | io_uring/poll.c        | GENMASK                   | 1          |
|          | io_uring/cancel.h      | io_cancel_remove_all      | 1          |
|          | io_uring/io_uring.h    | io_req_task_complete      | 1          |
|          | io_uring/io_uring.c    | init_waitqueue_func_entry | 1          |
|          | io_uring/io-wq.c       | spin_unlock_irq           | 1          |
|          | io_uring/poll.c        | add_wait_queue            | 2          |
|          | io_uring/cancel.c      | unlikely                  | 2          |
|          | io_uring/advise.c      | io_req_set_res            | 2          |

### xattr.c
| Source  | Library                | Function Utilized  | Times Used |
| ------- | ---------------------- | ------------------ | ---------- |
| xattr.c | io_uring/advise.c      | READ_ONCE          | 10         |
|         | io_uring/alloc_cache.c | kvfree             | 1          |
|         | io_uring/advise.c      | WARN_ON_ONCE       | 4          |
|         | io_uring/alloc_cache.c | kmalloc            | 2          |
|         | io_uring/advise.c      | io_req_set_res     | 1          |
|         | io_uring/xattr.c       | filename_getxattr  | 1          |
|         | io_uring/fs.c          | putname            | 1          |
|         | io_uring/epoll.c       | u64_to_user_ptr    | 6          |
|         | io_uring/advise.c      | io_kiocb_to_cmd    | 9          |
|         | io_uring/alloc_cache.h | kfree              | 3          |
|         | io_uring/cancel.c      | unlikely           | 2          |
|         | io_uring/xattr.c       | file_setxattr      | 1          |
|         | io_uring/xattr.c       | setxattr_copy      | 1          |
|         | io_uring/fs.c          | getname            | 2          |
|         | io_uring/xattr.c       | __io_setxattr_prep | 2          |
|         | io_uring/xattr.c       | file_getxattr      | 1          |
|         | io_uring/eventfd.c     | IS_ERR             | 2          |
|         | io_uring/eventfd.c     | PTR_ERR            | 2          |
|         | io_uring/xattr.c       | io_xattr_finish    | 4          |
|         | io_uring/xattr.c       | __io_getxattr_prep | 2          |
|         | io_uring/opdef.c       | io_xattr_cleanup   | 1          |
|         | io_uring/xattr.c       | import_xattr_name  | 1          |
|         | io_uring/xattr.c       | filename_setxattr  | 1          |

### zcrx.c
| Source | Library                | Function Utilized             | Times Used |
| ------ | ---------------------- | ----------------------------- | ---------- |
| zcrx.c | io_uring/zcrx.c        | page_pool_ref_netmem          | 1          |
|        | io_uring/eventfd.c     | PTR_ERR                       | 1          |
|        | io_uring/zcrx.c        | io_zcrx_ifq_free              | 2          |
|        | io_uring/zcrx.c        | net_iov_owner                 | 1          |
|        | io_uring/zcrx.c        | spin_unlock_bh                | 2          |
|        | io_uring/io_uring.h    | io_defer_get_uncommited_cqe   | 1          |
|        | io_uring/alloc_cache.h | kfree                         | 2          |
|        | io_uring/zcrx.c        | io_zcrx_sync_for_device       | 2          |
|        | io_uring/zcrx.c        | lock_sock                     | 1          |
|        | io_uring/eventfd.c     | IS_ERR                        | 1          |
|        | io_uring/rsrc.h        | io_buffer_validate            | 1          |
|        | io_uring/zcrx.c        | dma_dev_need_sync             | 1          |
|        | io_uring/io_uring.c    | percpu_ref_get                | 1          |
|        | io_uring/zcrx.c        | io_zcrx_alloc_fallback        | 1          |
|        | io_uring/cancel.c      | copy_from_user                | 3          |
|        | io_uring/zcrx.c        | io_zcrx_get_niov_uref         | 2          |
|        | io_uring/io-wq.c       | kzalloc                       | 2          |
|        | io_uring/zcrx.c        | net_mp_close_rxq              | 1          |
|        | io_uring/alloc_cache.c | kvfree                        | 4          |
|        | io_uring/zcrx.c        | netmem_is_net_iov             | 1          |
|        | io_uring/zcrx.c        | io_zcrx_copy_frag             | 1          |
|        | io_uring/zcrx.c        | io_zcrx_copy_chunk            | 2          |
|        | io_uring/zcrx.c        | kunmap_local                  | 2          |
|        | io_uring/zcrx.c        | put_device                    | 1          |
|        | io_uring/zcrx.c        | io_zcrx_iov_to_area           | 4          |
|        | io_uring/io_uring.c    | copy_to_user                  | 3          |
|        | io_uring/zcrx.c        | skb_headlen                   | 4          |
|        | io_uring/zcrx.c        | io_zcrx_ifq_alloc             | 1          |
|        | io_uring/zcrx.c        | spin_lock_bh                  | 4          |
|        | io_uring/zcrx.c        | io_zcrx_ring_refill           | 1          |
|        | io_uring/net.c         | skb_shinfo                    | 2          |
|        | io_uring/io_uring.c    | capable                       | 1          |
|        | io_uring/memmap.h      | io_pin_pages                  | 1          |
|        | io_uring/memmap.h      | io_create_region_mmap_safe    | 1          |
|        | io_uring/zcrx.c        | netdev_get_by_index           | 1          |
|        | io_uring/io_uring.c    | min_t                         | 4          |
|        | io_uring/epoll.c       | u64_to_user_ptr               | 5          |
|        | io_uring/zcrx.c        | net_mp_niov_set_page_pool     | 1          |
|        | io_uring/zcrx.c        | io_zcrx_refill_slow           | 1          |
|        | io_uring/zcrx.c        | release_sock                  | 1          |
|        | io_uring/zcrx.c        | io_zcrx_tcp_recvmsg           | 1          |
|        | io_uring/zcrx.c        | net_mp_netmem_place_in_cache  | 2          |
|        | io_uring/zcrx.c        | io_zcrx_create_area           | 1          |
|        | io_uring/memmap.h      | io_free_region                | 1          |
|        | io_uring/io-wq.c       | atomic_read                   | 2          |
|        | io_uring/fdinfo.c      | min                           | 1          |
|        | io_uring/zcrx.c        | io_allocate_rbuf_ring         | 1          |
|        | io_uring/zcrx.c        | io_free_rbuf_ring             | 1          |
|        | io_uring/zcrx.c        | io_zcrx_free_area             | 2          |
|        | io_uring/net.c         | sock_error                    | 1          |
|        | io_uring/zcrx.c        | io_zcrx_scrub                 | 1          |
|        | io_uring/io-wq.c       | atomic_inc                    | 1          |
|        | io_uring/io_uring.c    | smp_store_release             | 1          |
|        | io_uring/zcrx.c        | kmap_local_page               | 2          |
|        | io_uring/zcrx.c        | dma_map_page_attrs            | 1          |
|        | io_uring/zcrx.c        | page_pool_fragment_netmem     | 1          |
|        | io_uring/zcrx.c        | skb_walk_frags                | 1          |
|        | io_uring/zcrx.c        | page_pool_get_dma_addr_netmem | 2          |
|        | io_uring/eventfd.c     | atomic_set                    | 1          |
|        | io_uring/zcrx.c        | io_zcrx_drop_netdev           | 2          |
|        | io_uring/zcrx.c        | net_mp_niov_clear_page_pool   | 1          |
|        | io_uring/zcrx.c        | io_zcrx_get_rqe               | 1          |
|        | io_uring/zcrx.c        | net_mp_open_rxq               | 1          |
|        | io_uring/advise.c      | WARN_ON_ONCE                  | 5          |
|        | io_uring/zcrx.c        | io_zcrx_recv_skb              | 1          |
|        | io_uring/zcrx.c        | netdev_put                    | 2          |
|        | io_uring/cancel.c      | container_of                  | 1          |
|        | io_uring/zcrx.c        | io_get_user_counter           | 4          |
|        | io_uring/zcrx.c        | io_zcrx_queue_cqe             | 2          |
|        | io_uring/io_uring.c    | spin_lock_init                | 3          |
|        | io_uring/zcrx.c        | page_pool_put_unrefed_netmem  | 1          |
|        | io_uring/alloc_cache.c | kvmalloc_array                | 3          |
|        | io_uring/memmap.c      | unpin_user_pages              | 1          |
|        | io_uring/zcrx.c        | sock_flag                     | 2          |
|        | io_uring/zcrx.c        | io_zcrx_put_niov_uref         | 1          |
|        | io_uring/zcrx.c        | skb_frag_is_net_iov           | 1          |
|        | io_uring/zcrx.c        | __io_zcrx_unmap_area          | 2          |
|        | io_uring/zcrx.c        | io_zcrx_recv_frag             | 1          |
|        | io_uring/zcrx.c        | netmem_to_net_iov             | 2          |
|        | io_uring/zcrx.c        | skb_frag_size                 | 1          |
|        | io_uring/zcrx.c        | io_zcrx_return_niov           | 3          |
|        | io_uring/io_uring.c    | memcpy                        | 1          |
|        | io_uring/cancel.c      | lockdep_assert_held           | 3          |
|        | io_uring/zcrx.c        | dma_unmap_page_attrs          | 2          |
|        | io_uring/zcrx.c        | skb_frag_foreach_page         | 1          |
|        | io_uring/zcrx.c        | nla_nest_end                  | 1          |
|        | io_uring/zcrx.c        | sock_rps_record_flow          | 1          |
|        | io_uring/io_uring.c    | roundup_pow_of_two            | 1          |
|        | io_uring/io-wq.c       | likely                        | 1          |
|        | io_uring/zcrx.c        | nla_nest_start                | 1          |
|        | io_uring/zcrx.c        | io_zcrx_map_area              | 1          |
|        | io_uring/zcrx.c        | io_zcrx_iov_page              | 1          |
|        | io_uring/io_uring.c    | io_region_get_ptr             | 1          |
|        | io_uring/zcrx.c        | dma_mapping_error             | 1          |
|        | io_uring/zcrx.c        | io_close_queue                | 2          |
|        | io_uring/zcrx.c        | skb_frag_page                 | 1          |
|        | io_uring/cancel.c      | spin_lock                     | 2          |
|        | io_uring/zcrx.c        | WARN_ON                       | 2          |
|        | io_uring/zcrx.c        | __io_zcrx_get_free_niov       | 2          |
|        | io_uring/zcrx.c        | tcp_read_sock                 | 1          |
|        | io_uring/io_uring.c    | array_index_nospec            | 1          |
|        | io_uring/cancel.c      | spin_unlock                   | 2          |
|        | io_uring/zcrx.c        | net_mp_niov_set_dma_addr      | 2          |
|        | io_uring/io_uring.h    | smp_load_acquire              | 1          |
|        | io_uring/io_uring.c    | offsetof                      | 2          |
|        | io_uring/cancel.c      | unlikely                      | 10         |
|        | io_uring/zcrx.c        | get_device                    | 1          |
|        | io_uring/io-wq.c       | atomic_dec                    | 1          |
|        | io_uring/zcrx.c        | net_iov_to_netmem             | 8          |
|        | io_uring/zcrx.c        | io_zcrx_return_niov_freelist  | 2          |
|        | io_uring/zcrx.c        | io_zcrx_rqring_entries        | 1          |
|        | io_uring/zcrx.c        | __dma_sync_single_for_device  | 1          |
|        | io_uring/zcrx.c        | atomic_xchg                   | 1          |
|        | io_uring/zcrx.c        | net_iov_idx                   | 4          |
|        | io_uring/io_uring.c    | percpu_ref_put                | 1          |
|        | io_uring/zcrx.c        | io_zcrx_unmap_area            | 1          |
|        | io_uring/advise.c      | READ_ONCE                     | 1          |
|        | io_uring/zcrx.c        | skb_frag_off                  | 2          |
|        | io_uring/zcrx.c        | page_pool_unref_netmem        | 2          |
|        | io_uring/memmap.c      | memchr_inv                    | 1          |

## Headers

### advise.h

| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |



### alloc_cache.h

| Source        | Library                | Function Utilized             | Times Used |
| ------------- | ---------------------- | ----------------------------- | ---------- |
| alloc_cache.h | io_uring/alloc_cache.h | io_alloc_cache_put            | 1          |
|               | mm/slub.c              | kfree                         | 1          |
|               | io_uring/alloc_cache.c | io_alloc_cache_init           | 1          |
|               | include/linux/kasan.h  | kasan_mempool_unpoison_object | 1          |
|               | io_uring/alloc_cache.h | io_alloc_cache_get            | 1          |
|               | include/linux/string.h | memset                        | 1          |
|               | include/linux/kasan.h  | kasan_mempool_poison_object   | 1          |
|               | io_uring/alloc_cache.c | io_cache_alloc_new            | 2          |

### cancel.h

| Source   | Library           | Function Utilized | Times Used |
| -------- | ----------------- | ----------------- | ---------- |
| cancel.h | io_uring/cancel.c | io_cancel_remove  | 1          |




### epoll.h

| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |


### eventfd.h

| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |



### fdinfo.h

| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |


### filetable.h

| Source      | Library                   | Function Utilized | Times Used |
| ----------- | ------------------------- | ----------------- | ---------- |
| filetable.h | include/linux/bitops.h    | __set_bit         | 1          |
|             | include/asm-generic/bug.h | WARN_ON_ONCE      | 2          |
|             | include/linux/bitops.h    | __clear_bit       | 1          |
|             | include/linux/bitops.h    | test_bit          | 2          |
|             | io_uring/filetable.h,     | io_file_get_flags | 1          |



### fs.h

| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |


### futex.h

| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### io_uring.h
| Source File | Library/Header                             | Function                        | Times Used |
| ----------- | ------------------------------------------ | ------------------------------- | ---------- |
| io_uring.h  | include/linux/compiler.h                   | unlikely                        | 9          |
|             | include/linux/lockdep.h                    | lockdep_assert_held             | 7          |
|             | include/linux/sched.h                      | __set_current_state             | 3          |
|             | include/asm-generic/rwonce.h               | READ_ONCE                       | 3          |
|             | io_uring/io_uring.h                        | io_lockdep_assert_cq_locked     | 3          |
|             | io_uring/io_uring.h                        | io_local_work_pending           | 3          |
|             | io_uring/io_uring.h                        | io_get_cqe                      | 3          |
|             | include/linux/wait.h                       | wq_has_sleeper                  | 2          |
|             | kernel/sched/wait.c                        | __wake_up                       | 2          |
|             | include/linux/thread_info.h                | test_thread_flag                | 2          |
|             | io_uring/io_uring.h                        | tctx_task_work_run              | 2          |
|             | include/linux/task_work.h                  | task_work_pending               | 2          |
|             | io_uring/io_uring.h                        | io_req_set_res                  | 1          |
|             | io_uring/io_uring.c                        | __io_req_task_work_add          | 1          |
|             | include/linux/slab.h                       | kmalloc                         | 1          |
|             | include/linux/atomic/atomic-instrumented.h | atomic_read                     | 1          |
|             | include/linux/resume_user_mode.h           | resume_user_mode_work           | 1          |
|             | include/asm-generic/barrier.h              | smp_store_release               | 1          |
|             | kernel/task_work.c                         | task_work_run                   | 1          |
|             | include/asm-generic/barrier.h              | smp_load_acquire                | 1          |
|             | include/asm-generic/barrier.h              | __must_hold                     | 1          |
|             | io_uring/io_uring.h                        | io_get_cqe_overflow             | 1          |
|             | io_uring/slist.h                           | wq_list_add_tail                | 1          |
|             | io_uring/slist.h                           | fput                            | 1          |
|             | arch/alpha/include/asm/string.h            | memset                          | 1          |
|             | io_uring/io_uring.h                        | io_req_task_work_add            | 1          |
|             | io_uring/slist.h                           | wq_list_empty                   | 1          |
|             | io_uring/io_uring.c                        | io_task_refs_refill             | 1          |
|             | io_uring/slist.h                           | wq_stack_extract                | 1          |
|             | arch/alpha/include/asm/string.h            | memcpy                          | 2          |
|             | arch/arm/include/asm/uaccess-asm.h         | IS_ENABLED                      | 1          |
|             | include/linux/wait.h                       | poll_to_key                     | 2          |
|             | kernel/time/timekeeping.c                  | ktime_get_with_offset           | 1          |
|             | include/linux/sched/signal.h               | clear_notify_signal             | 1          |
|             | include/linux/mutex.h                      | mutex_lock                      | 1          |
|             | io_uring/io_uring.c                        | __io_commit_cqring_flush        | 1          |
|             | io_uring/io_uring.h                        | io_extract_req                  | 1          |
|             |                                            | trace_io_uring_complete         | 1          |
|             | include/linux/percpu-refcount.h            | percpu_ref_is_dying             | 1          |
|             | include/linux/lockdep.h                    | lockdep_assert                  | 2          |
|             | include/linux/compiler.h                   | likely                          | 2          |
|             | io_uring/alloc_cache.h                     | io_cache_alloc                  | 1          |
|             |                                            | file_can_poll                   | 1          |
|             | arch/arc/include/asm/arcregs.h             | min                             | 1          |
|             | include/asm-generic/bug.h                  | WARN_ON_ONCE                    | 1          |
|             | io_uring/io_uring.c                        | io_cqe_cache_refill             | 1          |
|             | include/linux/container_of.h               | container_of                    | 1          |
|             |                                            | trace_io_uring_complete_enabled | 1          |
|             | include/linux/preempt.h                    | in_task                         | 1          |
|             | arch/x86/boot/bitops.h                     | test_bit                        | 1          |
|             | io_uring/io_uring.c                        | __io_submit_flush_completions   | 1          |
|             | io_uring/io_uring.h                        | io_req_cache_empty              | 1          |
|             | include/linux/llist.h                      | llist_empty                     | 1          |
|             | include/linux/mutex.h                      | mutex_unlock                    | 1          |
|             | io_uring/io_uring.c                        | __io_alloc_req_refill           | 1          |
|             | kernel/time/timekeeping.c                  | ktime_get                       | 1          |

### io-wq.h
| Source File | Library/Header                             | Function              | Times Used |
| ----------- | ------------------------------------------ | --------------------- | ---------- |
| io-wq.h     | io_uring/io-wq.c                           | io_wq_cancel_cb       | 1          |
|             | include/linux/slab.h                       | kfree                 | 1          |
|             | include/linux/atomic/atomic-instrumented.h | atomic_read           | 1          |
|             | io_uring/io-wq.c                           | io_wq_worker_running  | 1          |
|             | include/linux/refcount.h                   | refcount_dec_and_test | 1          |
|             | include/linux/preempt.h                    | in_task               | 1          |
|             | io_uring/io-wq.c                           | io_wq_worker_sleeping | 1          |
|             | io_uring/io-wq.h                           | __io_wq_is_hashed     | 1          |

### kbuf.h
| Source File | Library/Header  | Function               | Times Used |
| ----------- | --------------- | ---------------------- | ---------- |
| kbuf.h      | io_uring/kbuf.c | io_kbuf_recycle_legacy | 1          |
|             | io_uring/kbuf.h | io_kbuf_recycle_ring   | 1          |
|             | io_uring/kbuf.c | __io_put_kbufs         | 2          |

### memmap.h
| Source File | Library/Header | Function | Times Used |
| ----------- | -------------- | -------- | ---------- |

### msg_ring.h
| Source File | Library/Header | Function | Times Used |
| ----------- | -------------- | -------- | ---------- |

### napi.h
| Source File | Library/Header               | Function            | Times Used |
| ----------- | ---------------------------- | ------------------- | ---------- |
| napi.h      | io_uring/napi.c              | __io_napi_add_id    | 1          |
|             | net/socket.c                 | sock_from_file      | 1          |
|             | io_uring/napi.h              | io_napi             | 1          |
|             | include/asm-generic/rwonce.h | READ_ONCE           | 2          |
|             | io_uring/napi.c              | __io_napi_busy_loop | 1          |
|             | include/linux/list.h         | list_empty          | 1          |

### net.h
| Source File | Library/Header | Function | Times Used |
| ----------- | -------------- | -------- | ---------- |

### nop.h
| Source File | Library/Header | Function | Times Used |
| ----------- | -------------- | -------- | ---------- |

### notif.h
| Source File | Library/Header                 | Function            | Times Used |
| ----------- | ------------------------------ | ------------------- | ---------- |
| notif.h     | io_uring/notif.c               | io_tx_ubuf_complete | 1          |
|             | include/linux/compiler_types.h | __must_hold         | 1          |
|             | include/linux/io_uring_types.h | io_kiocb_to_cmd     | 1          |
|             | io_uring/notif.h               | io_notif_to_data    | 2          |
|             | io_uring/rsrc.c                | __io_account_mem    | 1          |

### opdef.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### openclose.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### poll.h
| Source | Library                                  | Function Utilized | Times Used |
| ------ | ---------------------------------------- | ----------------- | ---------- |
| poll.h | drivers/infiniband/hw/bnxt_re/ib_verbs.c | atomic_inc        | 1          |

### refs.h
| Source | Library                                             | Function Utilized                 | Times Used |
| ------ | --------------------------------------------------- | --------------------------------- | ---------- |
| refs.h | include/linux/compiler.h                            | data_race                         | 1          |
|        | drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd_arcturus.c | WARN_ON_ONCE                      | 8          |
|        | arch/m68k/bvme6000/rtc.c                            | atomic_dec_and_test               | 2          |
|        | kernel/trace/trace_events.c                         | atomic_set                        | 1          |
|        | drivers/scsi/hpsa.h                                 | atomic_dec                        | 1          |
|        | arch/loongarch/kernel/perf_event.c                  | atomic_inc_not_zero               | 1          |
|        | block/blk.h                                         | req_ref_zero_or_close_to_overflow | 5          |
|        | drivers/net/wireless/ath/carl9170/debug.c           | atomic_read                       | 1          |
|        | include/linux/compiler.h                            | likely                            | 1          |
|        | drivers/infiniband/hw/bnxt_re/ib_verbs.c            | atomic_inc                        | 1          |

### register.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### rsrc.h
| Source | Library                        | Function Utilized       | Times Used |
| ------ | ------------------------------ | ----------------------- | ---------- |
| rsrc.h | include/linux/nospec.h         | array_index_nospec      | 1          |
|        | io_uring/rsrc.c                | io_put_rsrc_node        | 4          |
|        | arch/alpha/kernel/io.c         | IS_ENABLED              | 1          |
|        | io_uring/rsrc.h                | io_free_rsrc_node       | 2          |
|        | io_uring/rsrc.h                | io_vec_free             | 3          |
|        | include/linux/lockdep.h        | lockdep_assert_held     | 1          |
|        | arch/alpha/include/asm/local.h | atomic_long_sub         | 1          |
|        | io_uring/io_uring.c            | io_req_assign_rsrc_node | 2          |

### rw.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### slist.h
| Source  | Library                                    | Function Utilized | Times Used |
| ------- | ------------------------------------------ | ----------------- | ---------- |
| slist.h | include/asm-generic/rwonce.h               | WRITE_ONCE        | 3          |
|         | io_uring/slist.h                           | INIT_WQ_LIST      | 2          |
|         | drivers/usb/class/cdc-wdm.c                | READ_ONCE         | 1          |
|         | io_uring/slist.h                           | wq_list_empty     | 2          |
|         | io_uring/io-wq.c                           | wq_list_cut       | 2          |
|         | drivers/accel/habanalabs/common/hw_queue.c | container_of      | 1          |

### splice.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### sqpoll.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### statx.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### sync.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### tctx.h
| Source | Library          | Function Utilized                    | Times Used |
| ------ | ---------------- | ------------------------------------ | ---------- |
| tctx.h | io_uring/tctx.h  | __io_uring_add_tctx_node_from_submit | 1          |
|        | io_uring/io-wq.c | likely                               | 1          |

### timeout.h
| Source    | Library            | Function Utilized          | Times Used |
| --------- | ------------------ | -------------------------- | ---------- |
| timeout.h | io_uring/timeout.h | __io_disarm_linked_timeout | 1          |

### truncate.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### uring_cmd.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### waitid.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### xattr.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |

### zcrx.h
| Source | Library | Function Utilized | Times Used |
| ------ | ------- | ----------------- | ---------- |








