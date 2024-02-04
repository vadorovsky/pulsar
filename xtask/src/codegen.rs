use std::{fs::File, io::Write, path::PathBuf};

use anyhow::Result;
use aya_tool::generate::InputFile;

pub fn run() -> Result<()> {
    let dir = PathBuf::from("crates/modules/process-monitor-ebpf/src");
    let types: Vec<&str> = vec![
        "cgroup",
        "file",
        "kernfs_node",
        "linux_binprm",
        "list_head",
        "path",
        "signal_struct",
        "task_struct",
    ];
    let bindings = aya_tool::generate(
        InputFile::Header(PathBuf::from("crates/bpf-builder/include/x86_64/vmlinux.h")),
        &types,
        &[],
    )?;
    let mut out = File::create(dir.join("vmlinux.rs"))?;
    write!(out, "{}", bindings)?;

    Ok(())
}
