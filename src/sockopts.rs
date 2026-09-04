//! Platform-specific socket options for outgoing connections.
//!
//! On Linux, these use real syscalls (SO_MARK, SO_BINDTODEVICE).
//! On all other platforms, these are no-ops that return Ok(()).

/// Set the SO_MARK socket option on a raw file descriptor.
///
/// On Linux, this sets the netfilter mark on the socket, which can be used
/// by iptables and ip-rule for policy-based routing.
///
/// On non-Linux platforms, this is a no-op.
#[cfg(target_os = "linux")]
pub fn set_socket_mark(fd: std::os::unix::io::RawFd, mark: i32) -> std::io::Result<()> {
    use std::io;
    // SOL_SOCKET = 1, SO_MARK = 36 on Linux
    const SOL_SOCKET: libc::c_int = 1;
    const SO_MARK: libc::c_int = 36;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_SOCKET,
            SO_MARK,
            &mark as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_socket_mark(_fd: i32, _mark: i32) -> std::io::Result<()> {
    // SO_MARK is not supported on non-Linux platforms.
    Ok(())
}

/// Bind a socket to a specific network interface by name.
///
/// On Linux, this uses SO_BINDTODEVICE to force all traffic through the
/// named interface (e.g., "eth0", "wlan0").
///
/// On non-Linux platforms, this is a no-op.
#[cfg(target_os = "linux")]
pub fn set_socket_interface(fd: std::os::unix::io::RawFd, iface: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::io;

    const SOL_SOCKET: libc::c_int = 1;
    const SO_BINDTODEVICE: libc::c_int = 25;

    let c_iface =
        CString::new(iface).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_SOCKET,
            SO_BINDTODEVICE,
            c_iface.as_ptr() as *const libc::c_void,
            c_iface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_socket_interface(_fd: i32, _iface: &str) -> std::io::Result<()> {
    // SO_BINDTODEVICE is not supported on non-Linux platforms.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_socket_mark_noop_on_non_linux() {
        // On non-Linux (where this test runs), should be a no-op returning Ok
        // On Linux, would need a real fd
        #[cfg(not(target_os = "linux"))]
        {
            assert!(set_socket_mark(0, 100).is_ok());
        }
    }

    #[test]
    fn test_set_socket_interface_noop_on_non_linux() {
        #[cfg(not(target_os = "linux"))]
        {
            assert!(set_socket_interface(0, "eth0").is_ok());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_set_socket_mark_invalid_fd() {
        // fd -1 should fail on Linux
        let result = set_socket_mark(-1, 100);
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_set_socket_interface_invalid_fd() {
        let result = set_socket_interface(-1, "eth0");
        assert!(result.is_err());
    }
}
