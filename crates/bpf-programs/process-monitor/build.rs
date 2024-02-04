use anyhow::Result;

fn main() -> Result<()> {
    // Ok(())
    bpf_builder::build_shim("vmlinux_access.c", &["vmlinux_access.h"])
}
