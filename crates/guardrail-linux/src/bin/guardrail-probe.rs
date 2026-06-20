//! Test helper exercised by guardrail-linux integration tests.
//!
//! Usage: `guardrail-probe <COMMAND> [ARG]`
//!
//! Exit codes:
//!   0   operation succeeded / allowed
//!   3   operation failed because it was denied (the expected sandboxed result)
//!   2   usage error / unknown command
//!
//! Commands (this plan):
//!   echo-env <NAME>   print the value of env var NAME (empty if unset), exit 0
//!   alloc <MB>        try to allocate and touch <MB> megabytes; exit 0 if it
//!                     succeeds, exit 3 if allocation fails
//!   spin              busy-loop forever (for CPU-time-limit tests)
//!
//! Later plans add more commands (read-file, write-file, socket-inet, bind,
//! shm, ptrace, ...). Keep the dispatch table and exit-code contract stable.

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "echo-env" => {
            let name = args.get(2).map(String::as_str).unwrap_or("");
            print!("{}", std::env::var(name).unwrap_or_default());
            exit(0);
        }
        "alloc" => {
            let mb: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            // Allocate and touch every page so the kernel actually commits it.
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve(mb * 1024 * 1024).is_err() {
                exit(3);
            }
            v.resize(mb * 1024 * 1024, 0);
            let mut acc: u8 = 0;
            let mut i = 0;
            while i < v.len() {
                v[i] = 1;
                acc = acc.wrapping_add(v[i]);
                i += 4096;
            }
            // Use `acc` so the loop isn't optimized away.
            if acc == 123 {
                eprintln!("unreachable {acc}");
            }
            exit(0);
        }
        "spin" => loop {
            std::hint::spin_loop();
        },
        _ => {
            eprintln!("usage: guardrail-probe <echo-env|alloc|spin> [arg]");
            exit(2);
        }
    }
}
