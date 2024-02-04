use anyhow::Result;

fn main() -> Result<()> {
    bpf_builder::build("probes", "probes.bpf.c")
}
