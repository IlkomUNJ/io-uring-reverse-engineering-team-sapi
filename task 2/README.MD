# Task 2

## Source

### io_uring.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| io_uring.c                         | linux/slab.h                       | kmalloc                        | 12         |
| io_uring.c                         | linux/slab.h                       | kfree                          | 8          |
| io_uring.c                         | linux/fs.h                         | file_operations                | 6          |
| io_uring.c                         | linux/fs.h                         | file_get                       | 4          |
| io_uring.c                         | linux/fs.h                         | file_put                       | 4          |
| io_uring.c                         | linux/uaccess.h                    | copy_from_user                 | 5          |
| io_uring.c                         | linux/uaccess.h                    | copy_to_user                   | 5          |
| io_uring.c                         | linux/mm.h                         | get_user_pages                 | 3          |
| io_uring.c                         | linux/mm.h                         | put_page                       | 3          |
| io_uring.c                         | linux/sched.h                      | wake_up_process                | 3          |
| io_uring.c                         | linux/sched.h                      | set_current_state              | 2          |
| io_uring.c                         | io_uring.h                         | io_uring_setup                 | 2          |
| io_uring.c                         | io_uring.h                         | io_uring_enter                 | 2          |
| io_uring.c                         | io_uring.h                         | io_uring_register              | 2          |
| io_uring.c                         | linux/completion.h                 | complete                       | 2          |
| io_uring.c                         | linux/completion.h                 | wait_for_completion            | 2          |
| io_uring.c                         | linux/poll.h                       | poll_wait                      | 2          |
| io_uring.c                         | linux/kernel.h                     | pr_debug                       | 4          |
| io_uring.c                         | io-wq.h                            | io_wq_create                   | 1          |
| io_uring.c                         | io-wq.h                            | io_wq_destroy                  | 1          |
| io_uring.c                         | kbuf.h                             | io_buffer_select               | 2          |
| io_uring.c                         | rsrc.h                             | io_rsrc_node_destroy           | 1          |
| io_uring.c                         | notif.h                            | io_notif_flush                 | 1          |
| io_uring.c                         | linux/workqueue.h                  | schedule_work                  | 1          |

### io_uring.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| io_uring.h                         | linux/kernel.h                     | pr_err                         | 2          |
| io_uring.h                         | linux/kernel.h                     | pr_warn                        | 1          |
| io_uring.h                         | linux/sched.h                      | current                        | 3          |
| io_uring.h                         | linux/sched.h                      | task_pid_nr                    | 1          |
| io_uring.h                         | linux/fs.h                         | fput                           | 2          |
| io_uring.h                         | linux/fs.h                         | get_unused_fd_flags            | 1          |
| io_uring.h                         | linux/fs.h                         | fd_install                     | 1          |
| io_uring.h                         | linux/uaccess.h                    | copy_from_user                 | 2          |
| io_uring.h                         | linux/uaccess.h                    | copy_to_user                   | 2          |
| io_uring.h                         | linux/slab.h                       | kmalloc                        | 3          |
| io_uring.h                         | linux/slab.h                       | kfree                          | 2          |
| io_uring.h                         | linux/errno.h                      | IS_ERR                         | 1          |
| io_uring.h                         | linux/errno.h                      | PTR_ERR                        | 1          |
| io_uring.h                         | linux/completion.h                 | init_completion                | 1          |
| io_uring.h                         | linux/completion.h                 | wait_for_completion            | 1          |
| io_uring.h                         | linux/completion.h                 | complete                       | 1          |
| io_uring.h                         | linux/poll.h                       | poll_wait                      | 1          |
| io_uring.h                         | linux/workqueue.h                  | schedule_work                  | 1          |

### io-wq.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| io-wq.c                            | linux/slab.h                       | kmalloc                        | 5          |
| io-wq.c                            | linux/slab.h                       | kfree                          | 4          |
| io-wq.c                            | linux/sched.h                      | schedule                       | 3          |
| io-wq.c                            | linux/sched.h                      | wake_up_process                | 2          |
| io-wq.c                            | linux/sched.h                      | set_current_state              | 2          |
| io-wq.c                            | linux/completion.h                 | complete                       | 2          |
| io-wq.c                            | linux/completion.h                 | wait_for_completion            | 2          |
| io-wq.c                            | linux/kernel.h                     | pr_debug                       | 3          |
| io-wq.c                            | linux/kernel.h                     | pr_err                         | 2          |
| io-wq.c                            | linux/kernel.h                     | pr_warn                        | 1          |
| io-wq.c                            | linux/cpu.h                        | get_cpu                        | 1          |
| io-wq.c                            | linux/cpu.h                        | put_cpu                        | 1          |
| io-wq.c                            | linux/rcupdate.h                   | rcu_read_lock                  | 2          |
| io-wq.c                            | linux/rcupdate.h                   | rcu_read_unlock                | 2          |
| io-wq.c                            | linux/rculist_nulls.h              | hlist_nulls_add_head_rcu       | 1          |
| io-wq.c                            | linux/rculist_nulls.h              | hlist_nulls_del_rcu            | 1          |
| io-wq.c                            | linux/rculist_nulls.h              | hlist_nulls_for_each_entry_rcu | 1          |
| io-wq.c                            | linux/percpu.h                     | this_cpu_ptr                   | 1          |
| io-wq.c                            | linux/percpu.h                     | __this_cpu_add                 | 1          |
| io-wq.c                            | linux/percpu.h                     | __this_cpu_sub                 | 1          |
| io-wq.c                            | linux/cpuset.h                     | cpuset_cpus_allowed            | 1          |
| io-wq.c                            | linux/cpuset.h                     | cpumask_any_and                | 1          |
| io-wq.c                            | linux/cpuset.h                     | cpumask_any                    | 1          |
| io-wq.c                            | linux/workqueue.h                  | schedule_work                  | 1          |

### io-wq.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| io-wq.h                            | linux/kernel.h                     | pr_err                         | 1          |
| io-wq.h                            | linux/kernel.h                     | pr_warn                        | 1          |
| io-wq.h                            | linux/slab.h                       | kmalloc                        | 2          |
| io-wq.h                            | linux/slab.h                       | kfree                          | 1          |
| io-wq.h                            | linux/rcupdate.h                   | rcu_read_lock                  | 1          |
| io-wq.h                            | linux/rcupdate.h                   | rcu_read_unlock                | 1          |
| io-wq.h                            | linux/rculist_nulls.h              | hlist_nulls_add_head_rcu       | 1          |
| io-wq.h                            | linux/rculist_nulls.h              | hlist_nulls_del_rcu            | 1          |
| io-wq.h                            | linux/rculist_nulls.h              | hlist_nulls_for_each_entry_rcu | 1          |
| io-wq.h                            | linux/percpu.h                     | this_cpu_ptr                   | 1          |
| io-wq.h                            | linux/percpu.h                     | __this_cpu_add                 | 1          |
| io-wq.h                            | linux/percpu.h                     | __this_cpu_sub                 | 1          |
| io-wq.h                            | linux/cpuset.h                     | cpuset_cpus_allowed            | 1          |
| io-wq.h                            | linux/cpuset.h                     | cpumask_any_and                | 1          |
| io-wq.h                            | linux/cpuset.h                     | cpumask_any                    | 1          |

### kbuf.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| kbuf.c                             | linux/slab.h                       | kmalloc                        | 4          |
| kbuf.c                             | linux/slab.h                       | kfree                          | 3          |
| kbuf.c                             | linux/uaccess.h                    | copy_from_user                 | 2          |
| kbuf.c                             | linux/uaccess.h                    | copy_to_user                   | 2          |
| kbuf.c                             | linux/kernel.h                     | pr_err                         | 2          |
| kbuf.c                             | linux/kernel.h                     | pr_warn                        | 1          |
| kbuf.c                             | linux/mm.h                         | get_user_pages                 | 1          |
| kbuf.c                             | linux/mm.h                         | put_page                       | 1          |
| kbuf.c                             | linux/vmalloc.h                    | vzalloc                        | 1          |
| kbuf.c                             | linux/vmalloc.h                    | vfree                          | 1          |
| kbuf.c                             | linux/io_uring.h                   | io_alloc_notif                 | 1          |
| kbuf.c                             | linux/io_uring.h                   | io_free_notif                  | 1          |
| kbuf.c                             | kbuf.h                             | io_buffer_select               | 2          |
| kbuf.c                             | kbuf.h                             | io_kbuf_recycle_ring           | 1          |
| kbuf.c                             | kbuf.h                             | io_kbuf_recycle_legacy         | 1          |
| kbuf.c                             | kbuf.h                             | io_destroy_buffers             | 1          |

### kbuf.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| kbuf.h                             | linux/kernel.h                     | pr_err                         | 1          |
| kbuf.h                             | linux/kernel.h                     | pr_warn                        | 1          |
| kbuf.h                             | linux/slab.h                       | kmalloc                        | 2          |
| kbuf.h                             | linux/slab.h                       | kfree                          | 1          |
| kbuf.h                             | linux/uaccess.h                    | copy_from_user                 | 1          |
| kbuf.h                             | linux/uaccess.h                    | copy_to_user                   | 1          |
| kbuf.h                             | linux/mm.h                         | get_user_pages                 | 1          |
| kbuf.h                             | linux/mm.h                         | put_page                       | 1          |
| kbuf.h                             | linux/vmalloc.h                    | vzalloc                        | 1          |
| kbuf.h                             | linux/vmalloc.h                    | vfree                          | 1          |
| kbuf.h                             | linux/io_uring.h                   | io_alloc_notif                 | 1          |
| kbuf.h                             | linux/io_uring.h                   | io_free_notif                  | 1          |

### memmap.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| memmap.c                           | linux/slab.h                       | kmalloc                        | 3          |
| memmap.c                           | linux/slab.h                       | kfree                          | 2          |
| memmap.c                           | linux/mm.h                         | get_user_pages                 | 2          |
| memmap.c                           | linux/mm.h                         | put_page                       | 2          |
| memmap.c                           | linux/vmalloc.h                    | vzalloc                        | 1          |
| memmap.c                           | linux/vmalloc.h                    | vfree                          | 1          |
| memmap.c                           | linux/kernel.h                     | pr_err                         | 2          |
| memmap.c                           | linux/kernel.h                     | pr_warn                        | 1          |
| memmap.c                           | linux/io_uring.h                   | io_alloc_region                | 1          |
| memmap.c                           | linux/io_uring.h                   | io_free_region                 | 1          |
| memmap.c                           | memmap.h                           | io_create_region               | 2          |
| memmap.c                           | memmap.h                           | io_destroy_region              | 1          |

### memmap.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| memmap.h                           | linux/kernel.h                     | pr_err                         | 1          |
| memmap.h                           | linux/kernel.h                     | pr_warn                        | 1          |
| memmap.h                           | linux/mm.h                         | get_user_pages                 | 1          |
| memmap.h                           | linux/mm.h                         | put_page                       | 1          |
| memmap.h                           | linux/vmalloc.h                    | vzalloc                        | 1          |
| memmap.h                           | linux/vmalloc.h                    | vfree                          | 1          |
| memmap.h                           | linux/io_uring.h                   | io_alloc_region                | 1          |
| memmap.h                           | linux/io_uring.h                   | io_free_region                 | 1          |
| memmap.h                           | memmap.h                           | io_create_region               | 1          |
| memmap.h                           | memmap.h                           | io_destroy_region              | 1          |

### msg-ring.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| msg-ring.c                         | linux/slab.h                       | kmalloc                        | 3          |
| msg-ring.c                         | linux/slab.h                       | kfree                          | 2          |
| msg-ring.c                         | linux/uaccess.h                    | copy_from_user                 | 2          |
| msg-ring.c                         | linux/uaccess.h                    | copy_to_user                   | 2          |
| msg-ring.c                         | linux/kernel.h                     | pr_err                         | 2          |
| msg-ring.c                         | linux/kernel.h                     | pr_warn                        | 1          |
| msg-ring.c                         | linux/fs.h                         | fput                           | 1          |
| msg-ring.c                         | linux/fs.h                         | get_unused_fd_flags            | 1          |
| msg-ring.c                         | linux/fs.h                         | fd_install                     | 1          |
| msg-ring.c                         | linux/io_uring.h                   | io_msg_ring_prep               | 1          |
| msg-ring.c                         | linux/io_uring.h                   | io_msg_ring                    | 1          |
| msg-ring.c                         | linux/io_uring.h                   | io_msg_ring_cleanup            | 1          |
| msg-ring.c                         | msg-ring.h                         | io_uring_sync_msg_ring         | 1          |

### msg-ring.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| msg-ring.h                         | linux/io_uring.h                   | io_msg_ring_prep               | 1          |
| msg-ring.h                         | linux/io_uring.h                   | io_msg_ring                    | 1          |
| msg-ring.h                         | linux/io_uring.h                   | io_msg_ring_cleanup            | 1          |
| msg-ring.h                         | msg-ring.h                         | io_uring_sync_msg_ring         | 1          |

### napi.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| napi.c                             | linux/slab.h                       | kmalloc                        | 2          |
| napi.c                             | linux/slab.h                       | kfree                          | 2          |
| napi.c                             | linux/kernel.h                     | pr_err                         | 1          |
| napi.c                             | linux/kernel.h                     | pr_warn                        | 1          |
| napi.c                             | linux/list.h                       | list_add                       | 1          |
| napi.c                             | linux/list.h                       | list_del                       | 1          |
| napi.c                             | linux/rcupdate.h                   | rcu_read_lock                  | 1          |
| napi.c                             | linux/rcupdate.h                   | rcu_read_unlock                | 1          |
| napi.c                             | linux/rculist.h                    | hlist_add_head_rcu             | 1          |
| napi.c                             | linux/rculist.h                    | hlist_del_rcu                  | 1          |
| napi.c                             | linux/netdevice.h                  | napi_id                        | 1          |
| napi.c                             | linux/netdevice.h                  | napi_busy_poll                 | 1          |
| napi.c                             | linux/netdevice.h                  | napi_schedule                  | 1          |
| napi.c                             | linux/netdevice.h                  | napi_complete                  | 1          |

### napi.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| napi.h                             | linux/kernel.h                     | pr_err                         | 1          |
| napi.h                             | linux/kernel.h                     | pr_warn                        | 1          |
| napi.h                             | linux/netdevice.h                  | napi_id                        | 1          |
| napi.h                             | linux/netdevice.h                  | napi_busy_poll                 | 1          |
| napi.h                             | linux/netdevice.h                  | napi_schedule                  | 1          |
| napi.h                             | linux/netdevice.h                  | napi_complete                  | 1          |

### net.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| net.c                              | linux/slab.h                       | kmalloc                        | 4          |
| net.c                              | linux/slab.h                       | kfree                          | 3          |
| net.c                              | linux/uaccess.h                    | copy_from_user                 | 2          |
| net.c                              | linux/uaccess.h                    | copy_to_user                   | 2          |
| net.c                              | linux/kernel.h                     | pr_err                         | 2          |
| net.c                              | linux/kernel.h                     | pr_warn                        | 1          |
| net.c                              | linux/fs.h                         | sockfd_lookup                  | 1          |
| net.c                              | linux/fs.h                         | sockfd_put                     | 1          |
| net.c                              | linux/net.h                        | sock_create                    | 1          |
| net.c                              | linux/net.h                        | sock_release                   | 1          |
| net.c                              | linux/net.h                        | kernel_bind                    | 1          |
| net.c                              | linux/net.h                        | kernel_listen                  | 1          |
| net.c                              | linux/net.h                        | kernel_accept                  | 1          |
| net.c                              | linux/net.h                        | kernel_connect                 | 1          |
| net.c                              | linux/net.h                        | kernel_sendmsg                 | 1          |
| net.c                              | linux/net.h                        | kernel_recvmsg                 | 1          |
| net.c                              | linux/io_uring.h                   | io_sendmsg                     | 1          |
| net.c                              | linux/io_uring.h                   | io_recvmsg                     | 1          |
| net.c                              | linux/io_uring.h                   | io_accept                      | 1          |
| net.c                              | linux/io_uring.h                   | io_connect                     | 1          |

### net.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| net.h                              | linux/net.h                        | sock_create                    | 1          |
| net.h                              | linux/net.h                        | sock_release                   | 1          |
| net.h                              | linux/net.h                        | kernel_bind                    | 1          |
| net.h                              | linux/net.h                        | kernel_listen                  | 1          |
| net.h                              | linux/net.h                        | kernel_accept                  | 1          |
| net.h                              | linux/net.h                        | kernel_connect                 | 1          |
| net.h                              | linux/net.h                        | kernel_sendmsg                 | 1          |
| net.h                              | linux/net.h                        | kernel_recvmsg                 | 1          |
| net.h                              | linux/io_uring_types.h             | io_async_msghdr                | 1          |
| net.h                              | linux/io_uring_types.h             | io_sendmsg                     | 1          |
| net.h                              | linux/io_uring_types.h             | io_recvmsg                     | 1          |
| net.h                              | linux/io_uring_types.h             | io_accept                      | 1          |
| net.h                              | linux/io_uring_types.h             | io_connect                     | 1          |

### nop.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| nop.c                              | linux/slab.h                       | kmalloc                        | 2          |
| nop.c                              | linux/slab.h                       | kfree                          | 1          |
| nop.c                              | linux/kernel.h                     | pr_err                         | 1          |
| nop.c                              | linux/kernel.h                     | pr_warn                        | 1          |
| nop.c                              | linux/uaccess.h                    | copy_from_user                 | 1          |
| nop.c                              | linux/uaccess.h                    | copy_to_user                   | 1          |
| nop.c                              | linux/io_uring.h                   | io_nop_prep                    | 1          |
| nop.c                              | linux/io_uring.h                   | io_nop                         | 1          |

### nop.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| nop.h                              | linux/io_uring.h                   | io_nop_prep                    | 1          |
| nop.h                              | linux/io_uring.h                   | io_nop                         | 1          |

### notif.c
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| notif.c                            | linux/slab.h                       | kmalloc                        | 3          |
| notif.c                            | linux/slab.h                       | kfree                          | 2          |
| notif.c                            | linux/kernel.h                     | pr_err                         | 2          |
| notif.c                            | linux/kernel.h                     | pr_warn                        | 1          |
| notif.c                            | linux/uaccess.h                    | copy_from_user                 | 1          |
| notif.c                            | linux/uaccess.h                    | copy_to_user                   | 1          |
| notif.c                            | linux/io_uring.h                   | io_notif_flush                 | 1          |
| notif.c                            | linux/io_uring.h                   | io_alloc_notif                 | 1          |
| notif.c                            | linux/io_uring.h                   | io_free_notif                  | 1          |
| notif.c                            | notif.h                            | io_notif_tw_complete           | 1          |

### notif.h
| Source File                        | Library/Header                     | Function                       | Times Used |
|------------------------------------|------------------------------------|--------------------------------|------------|
| notif.h                            | linux/io_uring.h                   | io_notif_flush                 | 1          |
| notif.h                            | linux/io_uring.h                   | io_alloc_notif                 | 1          |
| notif.h                            | linux/io_uring.h                   | io_free_notif                  | 1          |
| notif.h                            | notif.h                            | io_notif_tw_complete           | 1          |