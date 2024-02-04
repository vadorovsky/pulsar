use anyhow::Result;

fn main() -> Result<()> {
    bpf_builder::build("test_lsm", "src/feature_autodetect/test_lsm.bpf.c")
}
