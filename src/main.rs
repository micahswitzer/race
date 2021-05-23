use std::convert::TryInto;
use std::process::Command;
use nix::sys::{ptrace, wait::{waitpid, WaitStatus::*}, signal::Signal::*};
use nix::Error::Sys;
use nix::unistd::Pid;
use nix::errno::Errno::*;
use libc::user_regs_struct;

const PROC: &'static str = "./test-app";

#[derive(Eq, PartialEq)]
enum State {
    Attach,
    SyscallBefore,
    SyscallAfter,
}

#[cfg(target_arch = "x86_64")]
fn print_regs(regs: &user_regs_struct) {
    println!("rax: {:016x}, rbx: {:016x}, rcx: {:016x}, rdx: {:016x}",
             regs.rax, regs.rbx, regs.rcx, regs.rdx);
    println!("rip: {:016x}, rsp: {:016x}, rbp: {:016x}",
             regs.rip, regs.rsp, regs.rbp);
}

#[cfg(target_arch = "x86")]
fn print_regs(regs: &user_regs_struct) {
    println!("eax: {:08x}, ebx: {:08x}, ecx: {:08x}, edx: {:08x}",
             regs.eax, regs.ebx, regs.ecx, regs.edx);
    println!("eip: {:08x}, esp: {:08x}, ebp: {:08x}",
             regs.eip, regs.esp, regs.ebp);
}

pub fn main() {
    println!("Spawning child process '{}'", PROC);
    let mut child = Command::new(PROC)
        .spawn()
        .expect("Failed to start child process");
    let pid = Pid::from_raw(child.id().try_into().unwrap());
    println!("Process with pid {} started", pid);
    ptrace::attach(pid)
        .expect("Failed to attach to target process");
    println!("Attached to target process");
    let mut state = State::Attach;
    loop {
        let status = waitpid(pid, None)
            .expect("Failed to waitpid");
        println!("{} is {:?}", pid, status);
        if let Exited(_, _) = status { break; }
        if state == State::SyscallBefore {
            println!("Before syscall:");
        } else if state == State::SyscallAfter {
            println!("After syscall");
        }
        print_regs(&ptrace::getregs(pid).expect("Failed to get the process' registers"));
        match status {
            Stopped(lpid, SIGSTOP) => {
                ptrace::syscall(lpid, None).expect("Failed to ptrace::syscall");
                state = State::SyscallBefore;
            },
            Stopped(lpid, sig) => {
                ptrace::syscall(lpid, match sig { SIGTRAP => None, _ => Some(sig) })
                    .expect("Failed to ptrace::cont");
                if sig == SIGTRAP {
                    state = match state {
                        State::SyscallBefore => State::SyscallAfter,
                        State::SyscallAfter => State::SyscallBefore,
                        _ => State::SyscallBefore
                    };
                }
            },
            _ => panic!("Bad status after waitpid: {:?}", status)
        }
    }
    match ptrace::detach(pid, None) {
        Err(Sys(ESRCH)) => { 
            println!("Target process has already exited");
            return;
        },
        Err(err) => println!("Error while detaching: {}", err),
        Ok(()) => println!("Detached from target process")
    }
    let status = child.wait()
        .expect("Failed to wait for target process to exit");
    println!("Target exited with code {}", status.code().unwrap());
}
