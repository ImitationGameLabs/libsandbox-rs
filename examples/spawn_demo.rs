//! Demonstrate the spawn() API for sandboxed child processes.
//!
//! `run()` captures output automatically but blocks until completion.
//! `spawn()` returns a [`Child`] handle for interactive use — the caller
//! decides when to read, write, wait, or kill.

fn main() {
    use libsandbox::{Sandbox, Stdio};
    use std::os::fd::AsFd;
    use std::time::Duration;

    let sandbox = Sandbox::builder().build().expect("failed to build sandbox");

    // --- Example 1: Quick spawn + wait ---
    //
    // The simplest pattern: spawn a short-lived command and wait.
    // Since we don't need to capture output, use Stdio::Null to avoid
    // filling the pipe buffer (which could deadlock for large output).
    println!("=== Example 1: spawn + wait ===\n");

    let child = sandbox
        .build_spawn("echo", &["hello", "from", "sandbox"])
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .start()
        .expect("failed to spawn child");

    println!("child pid: {}", child.pid());

    let status = child.wait().expect("failed to wait");
    println!("exit code: {}", status.code());
    println!("success: {}", status.success());

    // --- Example 2: Interactive stdin/stdout via pipes ---
    //
    // Use build_spawn() to configure Stdio::Pipe for stdin, then
    // write input, poll output, and wait.
    println!("\n=== Example 2: stdin → cat → stdout ===\n");

    let mut child = sandbox
        .build_spawn("cat", &[])
        .stdin(Stdio::Pipe)
        .start()
        .expect("failed to spawn cat");

    // Write to the child's stdin pipe and close it (signals EOF)
    if let Some(stdin_fd) = child.stdin_fd() {
        let _ = nix::unistd::write(stdin_fd.as_fd(), b"hello from stdin\n");
    }
    child.close_stdin();

    // Take ownership of the stdout pipe fd so we can read from it
    // without holding an immutable borrow on `child` (try_wait
    // requires &mut self).
    let stdout_fd = child.take_stdout_fd();

    // Poll stdout until child exits
    let mut output = Vec::new();
    if let Some(fd) = stdout_fd {
        // Set stdout pipe to non-blocking for polling
        let flags =
            nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_GETFL).expect("fcntl F_GETFL");
        let flags = nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK;
        nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_SETFL(flags)).expect("fcntl F_SETFL");

        let mut buf = [0u8; 4096];
        loop {
            // Read any available output first
            let n = nix::unistd::read(fd.as_fd(), &mut buf).unwrap_or(0);
            if n > 0 {
                output.extend_from_slice(&buf[..n]);
            }
            // Then check if child has exited
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Final drain
                    loop {
                        let n = nix::unistd::read(fd.as_fd(), &mut buf).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        output.extend_from_slice(&buf[..n]);
                    }
                    println!("stdout: {}", String::from_utf8_lossy(&output).trim());
                    println!("exit code: {}", status.code());
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break,
            }
        }
    }
}
