use anyhow::Result;

fn main() -> Result<()> {
    bpf_builder::build_rust("../../bpf-programs/process-monitor")
}
