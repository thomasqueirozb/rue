use std::{collections::HashMap, os::unix::process::CommandExt, process::Command};

use nix::sys::{
    ptrace::{self, AddressType},
    wait::waitpid,
};
use nix::unistd::Pid;
use owo_colors::OwoColorize;
use serde_json::Value;

enum Argument {
    CharPointer,
    Other,
}

struct Syscall {
    name: String,
    args: Vec<Argument>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let json: serde_json::Value = serde_json::from_str(include_str!("syscall.json"))?;
    let syscall_table: HashMap<u64, Syscall> = json["aaData"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let mut items = item.as_array().unwrap().iter();
            let rax = items.next().unwrap().as_u64().unwrap();
            let name = items.next().unwrap().as_str().unwrap().into();
            let args = items.skip(1).take(6);

            let args = args
                .filter_map(|v| v.as_object().unwrap().get("type"))
                .map(Value::as_str)
                .map(Option::unwrap)
                .map(|s| {
                    if s.starts_with("const char __user * ") || s.starts_with("char __user * ") {
                        Argument::CharPointer
                    } else {
                        Argument::Other
                    }
                })
                .collect();

            (rax, Syscall { name, args })
        })
        .collect();

    let mut command = Command::new("cat");
    command.arg("/etc/hosts");
    unsafe {
        command.pre_exec(|| {
            use nix::sys::ptrace::traceme;
            traceme().map_err(|e| e.into())
        });
    }

    let child = command.spawn()?;
    let child_pid = Pid::from_raw(child.id() as _);
    let res = waitpid(child_pid, None)?;
    eprintln!("first wait: {:?}", res.yellow());

    let mut is_sys_exit = false;
    loop {
        ptrace::syscall(child_pid, None)?;
        _ = waitpid(child_pid, None)?;
        if is_sys_exit {
            let regs = ptrace::getregs(child_pid)?;
            let syscall = &syscall_table[&regs.orig_rax];

            let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]; // See: man 2 syscall
            let args: Vec<String> = args
                .into_iter()
                .zip(&syscall.args)
                .map(|(reg, arg)| {
                    match arg {
                        Argument::CharPointer => {
                            format!(
                                "\"{}\"",
                                read_char_pointer(child_pid, reg).unwrap_or_default()
                            )
                        }
                        Argument::Other => format!("{reg:x}"),
                    }
                    .blue()
                    .to_string()
                })
                .collect();

            eprintln!(
                "{}({}) = {:x}",
                syscall.name.green(),
                args.join(", "),
                regs.rax.yellow()
            );
        }
        is_sys_exit = !is_sys_exit;
    }
}

fn read_char_pointer(pid: Pid, addr: u64) -> Result<String, ()> {
    let mut buffer = vec![];
    for addr in (addr..).step_by(8) {
        match ptrace::read(pid, addr as AddressType) {
            Ok(data) => {
                let data = data.to_le_bytes();
                match data.iter().position(|&b| b == 0u8) {
                    Some(position) => {
                        buffer.extend_from_slice(&data[..position]);
                        break;
                    }
                    None => buffer.extend_from_slice(&data),
                }
            }
            Err(_e) => break,
        }
    }

    Ok(String::from_utf8_lossy(&buffer[..]).into_owned())
}
