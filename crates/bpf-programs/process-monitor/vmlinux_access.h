#pragma once

#include "common.bpf.h"

#define ULONG_MAX 18446744073709551615U

/*
 * struct cgroup
 */
struct kernfs_node *cgroup_kn(struct cgroup *cgrp);

/*
 * struct path
 */
struct vfsmount *file_f_path_mnt(struct file *file);
struct dentry *file_f_path_dentry(struct file *file);

/*
 * struct kernfs_node
 */
u64 kernfs_node_id(struct kernfs_node *kn);

/*
 * struct linux_binprm
 */
struct file *linux_bimprm_file(struct linux_binprm *bprm);
int linux_binprm_argc(struct linux_binprm *bprm);
const char *linux_binprm_filename(struct linux_binprm *bprm);

/*
 * struct signal_struct
 */
int signal_struct_live_counter(struct signal_struct *signal);

/*
 * struct mm_struct
 */
unsigned long mm_struct_arg_start(struct mm_struct *mm);
unsigned long mm_struct_arg_end(struct mm_struct *mm);

/*
 * struct task_struct
 */
struct mm_struct *task_struct_mm(struct task_struct *task);
int task_struct_exit_code(struct task_struct *task);
int task_struct_pid(struct task_struct *task);
int task_struct_tgid(struct task_struct *task);
struct task_struct *task_struct_parent(struct task_struct *task);
struct list_head *task_struct_children_next(struct task_struct *task);
struct list_head *task_struct_sibling_next(struct task_struct *task);
struct task_struct *task_struct_group_leader(struct task_struct *task);
struct signal_struct *task_struct_signal(struct task_struct *task);