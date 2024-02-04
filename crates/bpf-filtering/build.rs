use anyhow::Result;

fn main() -> Result<()> {
    bpf_builder::build("filtering_example", "src/filtering_example.bpf.c")
}
