#![cfg(target_os = "linux")]

//! Post-fork liveness: `pre_exec` runs between `fork` and `exec` in the child
//! of a possibly multithreaded parent, so it may only use async-signal-safe
//! operations. A child that allocates or touches a lock another thread held
//! at fork time deadlocks before `exec`, hanging the spawn (issue #14).
//!
//! These tests spawn concurrently under deliberate allocator and stdio-lock
//! pressure, with a watchdog so such a hang fails deterministically instead
//! of wedging the suite. glibc repairs its own malloc and stdio locks across
//! fork, so this cannot reproduce every historical hazard on every libc; it
//! guards the contract — most notably that no `pre_exec` step ever takes a
//! Rust-side stdio lock, which is *not* reinitialized in the forked child.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use guardrail_core::Backend;
use guardrail_linux::LinuxBackend;

mod common;

const SPAWNER_THREADS: usize = 2;
const SPAWN_ROUNDS: usize = 16;
const WATCHDOG: Duration = Duration::from_secs(120);

#[test]
fn spawns_survive_contended_multithreaded_parent() {
    if !common::landlock_enforced() {
        eprintln!("skipping: Landlock not enforced on this kernel");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let mut churners = Vec::new();

    // Allocator churn: keep malloc busy so forks are likely to land while
    // another thread is mid-allocation.
    for _ in 0..2 {
        let stop = Arc::clone(&stop);
        churners.push(std::thread::spawn(move || {
            let mut sink: Vec<Vec<u8>> = Vec::new();
            let mut size = 1usize;
            while !stop.load(Ordering::Relaxed) {
                size = size % 4096 + 17;
                sink.push(vec![0u8; size]);
                if sink.len() > 64 {
                    sink.clear();
                }
            }
        }));
    }

    // Stdio-lock churn: repeatedly hold Rust's stderr lock so a forked child
    // whose pre_exec path printed (e.g. an eprintln! diagnostic) would
    // deadlock against it and trip the watchdog.
    {
        let stop = Arc::clone(&stop);
        churners.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let guard = std::io::stderr().lock();
                std::hint::black_box(&guard);
                drop(guard);
            }
        }));
    }

    // Spawn loops run on their own threads so a post-fork hang surfaces as a
    // watchdog timeout rather than a wedged test binary. The backend is
    // shared, matching how the Node binding reuses one Sandbox.
    let backend = Arc::new(LinuxBackend::new(common::base()).expect("backend"));
    let (tx, rx) = mpsc::channel();
    let mut spawners = Vec::new();
    for spawner in 0..SPAWNER_THREADS {
        let backend = Arc::clone(&backend);
        let tx = tx.clone();
        spawners.push(std::thread::spawn(move || {
            for round in 0..SPAWN_ROUNDS {
                let mut child = backend
                    .spawn(common::probe(&["echo-env", "PATH"]))
                    .expect("spawn");
                let status = child.wait().expect("wait");
                assert!(
                    status.success(),
                    "spawner {spawner} round {round}: probe failed: {status:?}"
                );
            }
            tx.send(()).expect("report spawn-loop completion");
        }));
    }
    drop(tx);

    // One deadline covers every spawner. Giving each receive a fresh timeout
    // could make two stuck spawners take almost 2 * WATCHDOG to fail.
    let deadline = Instant::now() + WATCHDOG;
    let mut timed_out = false;
    for _ in 0..SPAWNER_THREADS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(()) => {}
            Err(RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            // A spawner died without reporting; joining below resurfaces its
            // panic with the real failure.
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    stop.store(true, Ordering::Relaxed);
    for churner in churners {
        churner.join().expect("churner thread");
    }
    assert!(
        !timed_out,
        "sandboxed spawns did not complete within {WATCHDOG:?}; a pre_exec \
         step likely blocked on a lock or allocation after fork"
    );
    for spawner in spawners {
        if let Err(panic) = spawner.join() {
            std::panic::resume_unwind(panic);
        }
    }
}
