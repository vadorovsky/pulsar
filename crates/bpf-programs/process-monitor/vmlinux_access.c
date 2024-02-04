#include "vmlinux_access.h"

/*
 * struct cgroup
 */

struct kernfs_node *cgroup_kn(struct cgroup *cgrp) {
  if (cgrp == 0) {
    return 0;
  }
  return BPF_CORE_READ(cgrp, kn);
}

/*
 * struct file
 */

struct vfsmount *file_f_path_mnt(struct file *file) {
  if (file == 0) {
    return 0;
  }
  return BPF_CORE_READ(file, f_path.mnt);
}

struct dentry *file_f_path_dentry(struct file *file) {
  if (file == 0) {
    return 0;
  }
  return BPF_CORE_READ(file, f_path.dentry);
}

/*
 * struct kernfs_node
 */

u64 kernfs_node_id(struct kernfs_node *kn) {
  if (kn == 0) {
    return ULONG_MAX;
  }
  return BPF_CORE_READ(kn, id);
}

/*
 * struct linux_binprm
 */

struct file *linux_binprm_file(struct linux_binprm *bprm) {
  if (bprm == 0) {
    return 0;
  }
  return BPF_CORE_READ(bprm, file);
}

int linux_binprm_argc(struct linux_binprm *bprm) {
  if (bprm == 0) {
    return -1;
  }
  return BPF_CORE_READ(bprm, argc);
}

const char *linux_binprm_filename(struct linux_binprm *bprm) {
  if (bprm == 0) {
    return 0;
  }
  return BPF_CORE_READ(bprm, filename);
}

/*
 * struct signal_struct
 */

int signal_struct_live_counter(struct signal_struct *signal) {
  if (signal == 0) {
    return -1;
  }
  return BPF_CORE_READ(signal, live.counter);
}

/*
 * struct mm_struct
 */

unsigned long mm_struct_arg_start(struct mm_struct *mm) {
  if (mm == 0) {
    return ULONG_MAX;
  }
  return BPF_CORE_READ(mm, arg_start);
}

unsigned long mm_struct_arg_end(struct mm_struct *mm) {
  if (mm == 0) {
    return ULONG_MAX;
  }
  return BPF_CORE_READ(mm, arg_end);
}

/*
 * struct task_struct
 */

struct mm_struct *task_struct_mm(struct task_struct *task) {
  if (task == 0) {
    return 0;
  }
  return BPF_CORE_READ(task, mm);
}

int task_struct_exit_code(struct task_struct *task) {
  if (task == 0) {
    return -1;
  }
  return BPF_CORE_READ(task, exit_code);
}

int task_struct_pid(struct task_struct *task) {
  if (task == 0) {
    return -1;
  }
  return BPF_CORE_READ(task, pid);
}

int task_struct_tgid(struct task_struct *task) {
  if (task == 0) {
    return -1;
  }
  return BPF_CORE_READ(task, tgid);
}

struct task_struct *task_struct_parent(struct task_struct *task) {
  if (task == 0) {
    return 0;
  }
  return BPF_CORE_READ(task, parent);
}

struct list_head *task_struct_children_next(struct task_struct *task) {
  if (task == 0) {
    return 0;
  }
  return BPF_CORE_READ(task, children.next);
}

struct list_head *task_struct_sibling_next(struct task_struct *task) {
  if (task == 0) {
    return 0;
  }
  return BPF_CORE_READ(task, sibling.next);
}

struct task_struct *task_struct_group_leader(struct task_struct *task) {
  if (task == 0) {
    return 0;
  }
  return BPF_CORE_READ(task, group_leader);
}

struct signal_struct *task_struct_signal(struct task_struct *task) {
  if (task == 0) {
    return 0;
  }
  return BPF_CORE_READ(task, signal);
}
