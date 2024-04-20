#![allow(clippy::unwrap_used)]

use std::collections::HashSet;
use std::process::Command;
use std::str::from_utf8;

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

fn generate_rust_bindings(header: &str, preamble: &str, rust_file: &str) {
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let out_file = out_path.join(rust_file);
    println!("cargo:rerun-if-changed={}", out_file.display());
    // https://github.com/rust-lang/rust-bindgen/issues/687
    let ignored_macros = IgnoreMacros(HashSet::from(["IPPORT_RESERVED".into()]));
    bindgen::Builder::default()
        .clang_args(
            std::env::var("C_INCLUDE_PATH")
                .map(|path| {
                    if path.trim().is_empty() {
                        DEFAULT_INCLUDE_PATH.to_string()
                    } else {
                        path
                    }
                })
                .unwrap_or_else(|_| DEFAULT_INCLUDE_PATH.to_string())
                .split(':')
                .flat_map(|path| ["-isystem".to_string(), path.to_string()]),
        )
        .header_contents(header, &format!("{}\n#include <{}>", preamble, header))
        .parse_callbacks(Box::new(ignored_macros))
        .generate()
        .unwrap()
        .write_to_file(out_file.as_path())
        .unwrap();
}

const DEFAULT_INCLUDE_PATH: &str = "/usr/include";

fn generate_version() {
    let version = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .unwrap();
    let version = from_utf8(version.stdout.as_slice())
        .unwrap()
        .trim()
        .to_string();
    println!("cargo:rustc-env=CIJAIL_VERSION={}", version);
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");
    println!("cargo:rustc-rerun-if-changed=build.rs");
}

fn main() {
    generate_rust_bindings("sys/socket.h", "#define _GNU_SOURCE", "socket.rs");
    generate_version();
}
