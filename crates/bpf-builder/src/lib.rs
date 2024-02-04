use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    string::String,
};

use anyhow::{bail, Context};

static CLANG_DEFAULT: &str = "clang";
static LLVM_STRIP: &str = "llvm-strip";
static INCLUDE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/include");

// Given a probe name and the eBPF program source code path, compile it to OUT_DIR.
// We'll build multiple versions:
// - `${OUT_DIR}/{name}.5_13.bpf.o`: will contain the full version
// - `${OUT_DIR}/{name}.5_5.bpf.o`: will contain a version with the FEATURE_5_5 constant
//   defined. This version should be loaded on kernel < 5.13, see ../include/compatibility.bpf.h
pub fn build(name: &str, source: &str) -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed={source}");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/common.bpf.h");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/buffer.bpf.h");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/output.bpf.h");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/interest_tracking.bpf.h");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/loop.bpf.h");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/get_path.bpf.h");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/compatibility.bpf.h");

    let out_file = PathBuf::from(env::var("OUT_DIR")?).join(name);

    let out_file_5_13 = out_file.with_extension("5_13.bpf.o");
    compile(source, &out_file_5_13, &["-DVERSION_5_13"]).context("Error compiling 5.13 version")?;
    strip(&out_file_5_13).context("Error stripping 5.13 version")?;

    let out_file_5_5 = out_file.with_extension("5_5.bpf.o");
    compile(source, &out_file_5_5, &[]).context("Error compiling 5.5 version")?;
    strip(&out_file_5_5).context("Error stripping 5.5 version")?;

    Ok(())
}

pub fn build_rust<P>(crate_path: P) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    let crate_path_str = crate_path.as_ref().to_string_lossy();
    println!("cargo:rerun-if-changed={crate_path_str}");

    let mut cmd = Command::new("rustup");
    cmd.current_dir(crate_path)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .arg("run")
        .arg("nightly")
        .arg("cargo")
        .arg("build")
        .arg("--release");

    // Remove the current `CARGO_*` variables, they would mess with the build.`
    for (key, _) in env::vars() {
        if key.starts_with("CARGO_") {
            cmd.env_remove(&key);
        }
    }

    let status = cmd.status()?;
    if !status.success() {
        bail!("Failed to compile eBPF program");
    }

    Ok(())
}

/// Builds a shim for CO-RE access to kernel struct fields for BPF programs
/// written in Rust.
///
/// This is done due to lack of support of `preserve_access_index` LLVM
/// intrinsic (which makes CO-RE possible) in Rust. It's supported only by
/// clang.
///
/// Therefore, the shim for field access is written in C and linker to programs
/// written in Rust.
pub fn build_shim(shim_source: &str, headers: &[&str]) -> anyhow::Result<()> {
    let out_dir = env::var("OUT_DIR")?;
    let out_file = PathBuf::from(&out_dir)
        .join("vmlinux_access")
        .with_extension("bpf.o");
    compile(shim_source, &out_file, &["-emit-llvm", "-DSHIM"])?;

    let out_file = out_file.to_string_lossy();
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=link-arg={out_file}");
    println!("cargo:rerun-if-changed={shim_source}");
    for header in headers {
        println!("cargo:rerun-if-changed={header}");
    }

    Ok(())
}

fn compile<P>(source: &str, out_object: P, extra_args: &[&str]) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    let clang = env::var("CLANG").unwrap_or_else(|_| String::from(CLANG_DEFAULT));
    let arch = {
        let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        match arch.as_str() {
            // Architecture "bpf" means that we are building the BPF program
            // with rustc. Therefore, we need to retrieve the host architecture
            // through `bpf_target_arch` config.
            "bpf" => match env::var("CARGO_CFG_BPF_TARGET_ARCH") {
                Ok(arch) => arch,
                Err(_) => "x86_64".to_string(),
            },
            _ => arch,
        }
    };
    let include_path = PathBuf::from(INCLUDE_PATH);
    let status = Command::new(clang)
        .arg(format!("-I{}", include_path.to_string_lossy()))
        .arg(format!("-I{}", include_path.join(&arch).to_string_lossy()))
        .arg("-gdwarf-4")
        .arg("-O2")
        .args(["-target", "bpf"])
        .arg("-c")
        .arg("-Werror")
        .arg("-fno-stack-protector")
        .arg(format!(
            "-D__TARGET_ARCH_{}",
            match arch.as_str() {
                "x86_64" => "x86".to_string(),
                "aarch64" => "arm64".to_string(),
                "riscv64" => "riscv".to_string(),
                _ => arch.clone(),
            }
        ))
        .args(extra_args)
        .arg(source)
        .arg("-o")
        .arg(out_object.as_ref())
        .status()
        .context("Failed to execute clang")?;

    if !status.success() {
        bail!("Failed to compile eBPF program");
    }

    Ok(())
}

fn strip<P>(out_object: P) -> anyhow::Result<()>
where
    P: AsRef<Path>,
{
    // Strip debug symbols
    let status = Command::new(LLVM_STRIP)
        .arg("-g")
        .arg(out_object.as_ref())
        .status()
        .context("Failed to execute llvm-strip")?;

    if !status.success() {
        bail!("Failed strip eBPF program");
    }

    Ok(())
}
