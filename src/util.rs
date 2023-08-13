use std::ffi::{c_char, c_int};
use std::io;

/// Helper macro to execute a system call that returns an `io::Result`.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn setsockopt(
    fd: c_int,
    opt: c_int,
    val: c_int,
    payload: *const c_char,
    optlen: c_int,
) -> io::Result<()> {
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload.cast(),
        optlen as libc::socklen_t
    ))
    .map(|_| ())
}
