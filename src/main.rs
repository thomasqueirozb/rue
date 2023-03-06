use std::{collections::HashMap, os::unix::process::CommandExt, process::Command};

use nix::{
    sys::{ptrace, wait::waitpid},
    unistd::Pid,
};
use owo_colors::OwoColorize;
use serde_json::Value;

struct Syscall {
    name: String,
    args: Vec<String>,
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
                .map(String::from)
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
                .take(syscall.args.len())
                .map(|r| format!("{r:x}").blue().to_string())
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
