#![no_std]
#![no_main]

use aya_bpf::{
    cty::{c_char, c_int, c_long, c_ulong},
    macros::{kprobe, raw_tracepoint},
    programs::{ProbeContext, RawTracePointContext},
    BpfContext,
};

use process_monitor_events::{
    ExitEvent, ForkEvent, ProcessEvent, ProcessEventPayload, ProcessEventVariant,
};

mod maps;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{list_head, mm_struct, signal_struct, task_struct};

#[no_mangle]
static log_level: i32 = 0;

#[no_mangle]
static LINUX_KERNEL_VERSION: i32 = 0;

#[allow(improper_ctypes)]
extern "C" {
    fn cgroup_kn(cgrp: *const vmlinux::cgroup) -> *const vmlinux::kernfs_node;

    fn file_f_path_mnt(file: *const vmlinux::file) -> *const vmlinux::vfsmount;
    fn file_f_path_dentry(file: *const vmlinux::file) -> *const vmlinux::dentry;

    fn kernfs_node_id(kn: *const vmlinux::kernfs_node) -> u64;

    fn linux_binprm_file(bprm: *const vmlinux::linux_binprm) -> *const vmlinux::file;
    fn linux_binprm_argc(bprm: *const vmlinux::linux_binprm) -> c_int;
    fn linux_binprm_filename(bprm: *const vmlinux::linux_binprm) -> *const c_char;

    fn signal_struct_live_counter(signal: *const vmlinux::signal_struct) -> c_int;

    fn mm_struct_arg_start(mm: *const vmlinux::mm_struct) -> c_ulong;
    fn mm_struct_arg_end(mm: *const vmlinux::mm_struct) -> c_ulong;

    fn task_struct_mm(task: *const task_struct) -> *const mm_struct;
    fn task_struct_exit_code(task: *const task_struct) -> c_int;
    fn task_struct_pid(task: *const task_struct) -> c_int;
    fn task_struct_tgid(task: *const task_struct) -> c_int;
    fn task_struct_parent(task: *const task_struct) -> *const task_struct;
    fn task_struct_children_next(task: *const task_struct) -> *const list_head;
    fn task_struct_sibling_next(task: *const task_struct) -> *const list_head;
    fn task_struct_group_leader(task: *const task_struct) -> *const task_struct;
    fn task_struct_signal(task: *const task_struct) -> *const signal_struct;
}

pub struct Signal {
    ptr: *const signal_struct,
}

impl Signal {
    pub fn new(ptr: *const signal_struct) -> Self {
        Self { ptr }
    }

    pub fn live_counter(&self) -> Result<c_int, c_long> {
        let live_counter = unsafe { signal_struct_live_counter(self.ptr) };
        if live_counter < 0 {
            return Err(live_counter.into());
        }
        Ok(live_counter)
    }
}

pub struct Task {
    ptr: *const task_struct,
}

impl Task {
    pub fn new(ptr: *const task_struct) -> Self {
        Self { ptr }
    }

    pub fn exit_code(&self) -> Result<c_int, c_long> {
        let exit_code = unsafe { task_struct_exit_code(self.ptr) };
        if exit_code < 0 {
            return Err(exit_code.into());
        }
        Ok(exit_code)
    }

    pub fn pid(&self) -> Result<c_int, c_long> {
        let pid = unsafe { task_struct_pid(self.ptr) };
        if pid < 0 {
            return Err(pid.into());
        }
        Ok(pid)
    }

    pub fn tgid(&self) -> Result<c_int, c_long> {
        let tgid = unsafe { task_struct_tgid(self.ptr) };
        if tgid < 0 {
            return Err(tgid.into());
        }
        Ok(tgid)
    }

    pub fn parent(&self) -> Result<Self, c_long> {
        let ptr = unsafe { task_struct_parent(self.ptr) };
        if ptr.is_null() {
            return Err(-1);
        }
        Ok(Self { ptr })
    }

    pub fn group_leader(&self) -> Result<Self, c_long> {
        let ptr = unsafe { task_struct_group_leader(self.ptr) };
        if ptr.is_null() {
            return Err(-1);
        }
        Ok(Self { ptr })
    }

    pub fn signal(&self) -> Result<Signal, c_long> {
        let ptr = unsafe { task_struct_signal(self.ptr) };
        if ptr.is_null() {
            return Err(-1);
        }
        Ok(Signal::new(ptr))
    }
}

#[kprobe]
pub fn security_task_alloc(ctx: ProbeContext) -> u32 {
    match try_security_task_alloc(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_security_task_alloc(ctx: ProbeContext) -> Result<(), c_long> {
    // let task = Task::new(ctx.arg(0).ok_or(-1)?);
    let task: *const task_struct = ctx.arg(0).ok_or(-1)?;
    handle_task_alloc(&ctx, task)?;
    Ok(())
}

// fn handle_task_alloc<C>(ctx: &C, task: Task) -> Result<(), c_long>
fn handle_task_alloc<C>(ctx: &C, task: *const task_struct) -> Result<(), c_long>
where
    C: BpfContext,
{
    // let pid = task.pid()?;
    // let tgid = task.tgid()?;
    // let tgid = task.pid()?;
    let tgid = unsafe { task_struct_tgid(task) };

    maps::map_output_process_event.output(
        ctx,
        &ProcessEvent {
            timestamp: 0,
            pid: tgid,
            payload: ProcessEventPayload {
                event_type: 0,
                payload: ProcessEventVariant {
                    fork: ForkEvent { ppid: tgid },
                },
            },
        },
        0,
    );

    Ok(())
}

#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn sched_process_exit(ctx: RawTracePointContext) {
    let _ = try_sched_process_exit(ctx);
}

fn try_sched_process_exit(ctx: RawTracePointContext) -> Result<(), c_long> {
    let task = Task::new(ctx.as_ptr() as *const _);

    // if task.signal()?.live_counter()? > 0 {
    //     return Ok(());
    // }

    // let tgid = task.group_leader()?.pid()?;
    let tgid = task.tgid()?;
    let exit_code: u32 = task.exit_code()?.try_into().map_err(|_| -1)?;

    maps::map_output_process_event.output(
        &ctx,
        &ProcessEvent {
            timestamp: 0,
            pid: tgid,
            payload: ProcessEventPayload {
                event_type: 1,
                payload: ProcessEventVariant {
                    exit: ExitEvent { exit_code },
                },
            },
        },
        0,
    );

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
