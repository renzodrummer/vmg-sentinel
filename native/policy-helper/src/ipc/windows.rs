//! Windows named pipe with an ACL that denies Anonymous, plus a client-token check.
//! Product install runs this process as LocalSystem; Interactive users may connect.
//!
//! The DACL is set at CreateNamedPipe time. Changing it afterward with
//! SetKernelObjectSecurity needs WRITE_DAC on the handle, which even an
//! elevated process often does not have — that was the misleading Access denied log.

use crate::auth::PeerIdentity;
use crate::ipc::protocol::PIPE_SDDL;
use crate::ipc::serve::serve_connection;
use crate::state::HelperState;
use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

pub async fn listen(pipe_name: String, state: Arc<HelperState>) -> io::Result<()> {
    let path = format!(r"\\.\pipe\{pipe_name}");
    let mut server = match create_pipe(&path, true) {
        Ok(server) => server,
        Err(error) if error.raw_os_error() == Some(5) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Access denied creating \\\\.\\pipe\\vmg-sentinel-helper. Another helper is already running, or this process is not Administrator. End every vmg-sentinel-helper.exe in Task Manager, then run the helper as Administrator.",
            ));
        }
        Err(error) => return Err(error),
    };
    eprintln!("vmg-sentinel-helper pipe ready {path}");

    loop {
        server.connect().await?;
        let connected = server;
        server = create_pipe(&path, false)?;
        let peer = peer_identity(&connected).unwrap_or_else(|error| {
            eprintln!("policy-helper: peer identity failed: {error}");
            PeerIdentity::unauthenticated()
        });
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(connected, peer, state).await {
                eprintln!("policy-helper connection error: {error}");
            }
        });
    }
}

fn create_pipe(path: &str, first: bool) -> io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first);
    options.reject_remote_clients(true);

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(PIPE_SDDL),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .is_ok()
        {
            let mut attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            let result = options.create_with_security_attributes_raw(
                path,
                &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void,
            );
            let _ = LocalFree(HLOCAL(sd.0 as _));
            return result;
        }
    }
    options.create(path)
}

fn as_handle(pipe: &NamedPipeServer) -> HANDLE {
    HANDLE(pipe.as_raw_handle() as _)
}

fn peer_identity(pipe: &NamedPipeServer) -> windows::core::Result<PeerIdentity> {
    unsafe {
        let handle = as_handle(pipe);
        let mut pid = 0u32;
        GetNamedPipeClientProcessId(handle, &mut pid)?;

        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        let mut token = HANDLE::default();
        let token_result = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        let _ = CloseHandle(process);
        token_result?;

        let mut returned = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut returned);
        let mut buf = vec![0u8; returned as usize];
        let info_result = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            returned,
            &mut returned,
        );
        if info_result.is_err() {
            let _ = CloseHandle(token);
            return info_result.map(|_| unreachable!());
        }

        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str = windows::core::PWSTR::null();
        let sid_result = ConvertSidToStringSidW(user.User.Sid, &mut sid_str);
        let _ = CloseHandle(token);
        sid_result?;

        let sid = sid_str.to_string().unwrap_or_default();
        let _ = LocalFree(HLOCAL(sid_str.as_ptr() as _));
        let anonymous = sid.eq_ignore_ascii_case("S-1-5-7");
        Ok(PeerIdentity {
            authenticated: !anonymous,
            anonymous,
            process_id: pid,
        })
    }
}
