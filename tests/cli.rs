#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::process::Command;

use test_bin::get_test_bin;

mod dns_server;
use crate::dns_server::DnsServer;

#[test]
fn dig() {
    let (dns_server, socketaddr) =
        DnsServer::new([("name.tld".into(), "127.0.0.1".parse().unwrap())].into());
    dns_server.clone().spawn();
    let dig_args = vec![
        "dig".to_string(),
        format!("@{}", socketaddr.ip()),
        "-p".to_string(),
        socketaddr.port().to_string(),
        "+timeout=2".to_string(),
        "name.tld".to_string(),
    ];
    assert_failure(9, get_test_bin("cijail").args(dig_args.clone()));
    assert_failure(
        9,
        get_test_bin("cijail")
            .env("CIJAIL_ENDPOINTS", socketaddr.to_string())
            .args(dig_args.clone()),
    );
    assert_success(
        get_test_bin("cijail")
            .env("CIJAIL_ENDPOINTS", format!("{} name.tld", socketaddr))
            .args(dig_args),
    );
    dns_server.stop();
}

#[test]
fn read_dev_mem() {
    let sh_args = vec!["/bin/sh", "-c", "exec head -n1 /dev/mem"];
    assert_failure(1, get_test_bin("cijail").args(sh_args.clone()));
}

#[test]
fn read_dev_mem_symlink() {
    let sh_args = vec![
        "/bin/sh",
        "-c",
        r#"
set -e
tmpdir=$(mktemp -d)
ln -s /dev/mem $tmpdir/mem
exec head -n1 $tmpdir/mem
"#,
    ];
    assert_failure(1, get_test_bin("cijail").args(sh_args.clone()));
}

#[test]
fn read_proc_mem() {
    let sh_args = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!(
            r#"
set -e
for i in /proc/*/exe; do
    filename="$(readlink "$i" || true)"
    if ! expr "$filename" : '.*cijail$' >/dev/null; then
        continue
    fi
    mem="$(dirname "$i")"/mem
    cat "$mem" "$filename" >/dev/null
done
"#
        ),
    ];
    assert_failure(1, get_test_bin("cijail").args(sh_args.clone()));
}

fn assert_success(command: &mut Command) {
    match command.status() {
        Ok(status) => match status.code() {
            Some(code) if code != 0 => {
                panic!("failed to run `{}`: exit code {}", get_args(command), code);
            }
            None => {
                panic!(
                    "failed to run `{}`: terminated by signal",
                    get_args(command)
                );
            }
            _ => {}
        },
        Err(e) => {
            panic!("failed to run `{}`: {}", get_args(command), e);
        }
    }
}

fn assert_failure(expected_code: i32, command: &mut Command) {
    match command.status() {
        Ok(status) => match status.code() {
            Some(code) if code == expected_code => {}
            Some(code) => {
                panic!(
                    "failed to run `{}`: exit code {}, expected {}",
                    get_args(command),
                    code,
                    expected_code
                );
            }
            None => {
                panic!(
                    "failed to run `{}`: terminated by signal",
                    get_args(command)
                );
            }
        },
        Err(e) => {
            panic!("failed to run `{}`: {}", get_args(command), e);
        }
    }
}

fn get_args(command: &Command) -> String {
    let mut args: Vec<String> = Vec::new();
    args.push(command.get_program().to_string_lossy().to_string());
    args.extend(command.get_args().map(|x| x.to_string_lossy().to_string()));
    args.join(" ")
}
