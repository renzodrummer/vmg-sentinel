use crate::HardwareSnapshot;

pub fn poll() -> HardwareSnapshot {
    crate::empty_unavailable("linux_out_of_scope")
}