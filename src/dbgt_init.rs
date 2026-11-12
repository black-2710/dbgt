//! `dbgt init` — a pwninit-style helper: point it at a target binary and a
//! libc/ld pair, and it patches the binary to use them.
//!
//! This shells out to `patchelf` rather than reimplementing ELF interpreter
//! and NEEDED-entry rewriting. That's exactly what pwninit itself does:
//! growing a PT_INTERP segment and rewriting the dynamic section correctly
//! (without corrupting the file) is a solved problem in a tool everyone
//! already trusts for it, not something worth re-deriving by hand here.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(name = "dbgt init", about = "pwninit-style libc/ld patching for a target binary")]
pub struct InitArgs {
    /// Target binary to patch
    pub binary: PathBuf,
    /// libc to use (its NEEDED entry in the binary is pointed at this file)
    #[arg(long)]
    pub libc: Option<PathBuf>,
    /// Dynamic linker/loader to use as the binary's interpreter; if omitted
    /// and --libc is given, dbgt looks for a sibling ld-linux*.so* next to it
    #[arg(long)]
    pub ld: Option<PathBuf>,
    /// Write the patched binary here instead of patching it in place
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Make the binary (and the libc/ld, if given) executable
    #[arg(short, long)]
    pub chmod: bool,
}

pub fn run(args: InitArgs) -> Result<()> {
    check_patchelf()?;

    let target = match &args.output {
        Some(out) => {
            std::fs::copy(&args.binary, out).with_context(|| format!("copying {} to {}", args.binary.display(), out.display()))?;
            out.clone()
        }
        None => args.binary.clone(),
    };

    if args.chmod {
        chmod_exec(&target)?;
    }

    let ld = args.ld.clone().or_else(|| args.libc.as_ref().and_then(|l| find_sibling_ld(l)));

    if let Some(libc) = &args.libc {
        if !libc.exists() {
            bail!("libc not found: {}", libc.display());
        }
        if args.chmod {
            chmod_exec(libc)?;
        }
        match find_needed_libc(&target)? {
            Some(old) => {
                run_patchelf(&["--replace-needed", &old, &libc.to_string_lossy(), &target.to_string_lossy()])?;
                println!("replaced NEEDED '{old}' -> {}", libc.display());
            }
            None => println!("warning: no libc-looking NEEDED entry found in {} — leaving NEEDED unchanged", target.display()),
        }
    }

    if let Some(ld) = &ld {
        if !ld.exists() {
            bail!("ld not found: {}", ld.display());
        }
        if args.chmod {
            chmod_exec(ld)?;
        }
        run_patchelf(&["--set-interpreter", &ld.to_string_lossy(), &target.to_string_lossy()])?;
        println!("set interpreter -> {}", ld.display());
    } else if args.libc.is_some() {
        println!("note: no --ld given and none found next to the libc; interpreter left unchanged");
    }

    println!("done: {}", target.display());
    Ok(())
}

fn check_patchelf() -> Result<()> {
    let ok = Command::new("patchelf").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    if ok {
        Ok(())
    } else {
        bail!("`patchelf` not found on $PATH — install it first (e.g. apt install patchelf)")
    }
}

fn chmod_exec(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?.permissions();
    perm.set_mode(perm.mode() | 0o111);
    std::fs::set_permissions(path, perm).with_context(|| format!("chmod +x {}", path.display()))
}

/// A sibling `ld-linux*.so*` next to the given libc file, if there is one.
fn find_sibling_ld(libc: &Path) -> Option<PathBuf> {
    let dir = libc.parent()?;
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("ld-linux") && n.contains(".so")))
}

/// The binary's existing NEEDED entry that looks like libc, via `patchelf --print-needed`.
fn find_needed_libc(binary: &Path) -> Result<Option<String>> {
    let out = Command::new("patchelf").arg("--print-needed").arg(binary).output().context("running patchelf --print-needed")?;
    if !out.status.success() {
        bail!("patchelf --print-needed failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.lines().map(str::trim).find(|l| l.contains("libc.so")).map(str::to_string))
}

fn run_patchelf(args: &[&str]) -> Result<()> {
    let out = Command::new("patchelf").args(args).output().context("running patchelf")?;
    if !out.status.success() {
        bail!("patchelf {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}
