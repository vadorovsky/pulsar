#![no_std]
#![no_main]

use aya_bpf_cty::c_int;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BufferIndex {
    pub start: u16,
    pub len: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub ppid: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub filename: BufferIndex,
    pub args: c_int,
    pub argv: BufferIndex,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub exit_code: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChangeParentEvent {
    pub ppid: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupEvent {
    pub path: BufferIndex,
    pub id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupAttachEvent {
    pub pid: c_int,
    pub path: BufferIndex,
    pub id: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ProcessEventVariant {
    pub fork: ForkEvent,
    pub exec: ExecEvent,
    pub exit: ExitEvent,
    pub change_parent: ChangeParentEvent,
    pub cgroup_mkdir: CgroupEvent,
    pub cgroup_rmdir: CgroupEvent,
    pub cgroup_attach: CgroupAttachEvent,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEventPayload {
    pub event_type: u32,
    pub payload: ProcessEventVariant,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Buffer {
    pub len: usize,
    pub buffer: [u64; 2048],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub timestamp: u64,
    pub pid: c_int,
    pub payload: ProcessEventPayload,
}
