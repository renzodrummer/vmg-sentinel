//! Who this process is running as. Product path is LocalSystem (service),
//! not a per-user UAC elevation.

pub fn current() -> &'static str {
    #[cfg(windows)]
    {
        if is_local_system() {
            "LocalSystem"
        } else if unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() } {
            "admin"
        } else {
            "user"
        }
    }
    #[cfg(not(windows))]
    {
        "user"
    }
}

pub fn needs_service() -> bool {
    current() == "user"
}

#[cfg(windows)]
fn is_local_system() -> bool {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .is_ok();
        let _ = CloseHandle(token);
        if !ok {
            return false;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str = PWSTR::null();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_str).is_err() {
            return false;
        }
        let text = sid_str.to_string().unwrap_or_default();
        let _ = LocalFree(HLOCAL(sid_str.as_ptr() as _));
        text.eq_ignore_ascii_case("S-1-5-18")
    }
}
