use crate::executor::ExitStatus;

/// Type of crash detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashType {
    /// Segmentation fault (SIGSEGV)
    SegFault,
    /// Bus error (SIGBUS)
    BusError,
    /// Abort (SIGABRT)
    Abort,
    /// Floating point exception (SIGFPE)
    FloatingPoint,
    /// Illegal instruction (SIGILL)
    IllegalInstruction,
    /// Execution timeout
    Timeout,
    /// AddressSanitizer: heap-buffer-overflow
    AsanHeapOverflow,
    /// AddressSanitizer: stack-buffer-overflow
    AsanStackOverflow,
    /// AddressSanitizer: heap-use-after-free
    AsanUseAfterFree,
    /// AddressSanitizer: null pointer dereference
    AsanNullDeref,
    /// Unknown crash type
    Unknown,
}

impl CrashType {
    /// Get human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            CrashType::SegFault => "Segmentation Fault",
            CrashType::BusError => "Bus Error",
            CrashType::Abort => "Abort",
            CrashType::FloatingPoint => "Floating Point Exception",
            CrashType::IllegalInstruction => "Illegal Instruction",
            CrashType::Timeout => "Timeout",
            CrashType::AsanHeapOverflow => "ASAN: Heap Buffer Overflow",
            CrashType::AsanStackOverflow => "ASAN: Stack Buffer Overflow",
            CrashType::AsanUseAfterFree => "ASAN: Use After Free",
            CrashType::AsanNullDeref => "ASAN: Null Pointer Dereference",
            CrashType::Unknown => "Unknown",
        }
    }

    /// Check if this is a memory corruption bug.
    pub fn is_memory_corruption(&self) -> bool {
        matches!(
            self,
            CrashType::SegFault
                | CrashType::BusError
                | CrashType::AsanHeapOverflow
                | CrashType::AsanStackOverflow
                | CrashType::AsanUseAfterFree
                | CrashType::AsanNullDeref
        )
    }
}

/// Classify a crash from exit status.
pub fn triage_from_status(status: &ExitStatus) -> CrashType {
    match status {
        ExitStatus::Normal(_) => CrashType::Unknown,
        ExitStatus::Timeout => CrashType::Timeout,
        ExitStatus::Signal(sig) => triage_from_signal(*sig),
    }
}

/// Classify a crash from signal number.
pub fn triage_from_signal(sig: i32) -> CrashType {
    match sig {
        libc::SIGSEGV => CrashType::SegFault,
        libc::SIGBUS => CrashType::BusError,
        libc::SIGABRT => CrashType::Abort,
        libc::SIGFPE => CrashType::FloatingPoint,
        libc::SIGILL => CrashType::IllegalInstruction,
        _ => CrashType::Unknown,
    }
}

/// Try to classify from ASAN output.
pub fn triage_from_asan(output: &str) -> Option<CrashType> {
    if output.contains("heap-buffer-overflow") {
        Some(CrashType::AsanHeapOverflow)
    } else if output.contains("stack-buffer-overflow") {
        Some(CrashType::AsanStackOverflow)
    } else if output.contains("heap-use-after-free") {
        Some(CrashType::AsanUseAfterFree)
    } else if output.contains("SEGV on unknown address 0x000000000000") {
        Some(CrashType::AsanNullDeref)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crash_type_names() {
        assert_eq!(CrashType::SegFault.name(), "Segmentation Fault");
        assert_eq!(CrashType::Timeout.name(), "Timeout");
        assert_eq!(
            CrashType::AsanHeapOverflow.name(),
            "ASAN: Heap Buffer Overflow"
        );
    }

    #[test]
    fn test_crash_type_memory_corruption() {
        assert!(CrashType::SegFault.is_memory_corruption());
        assert!(CrashType::AsanHeapOverflow.is_memory_corruption());
        assert!(!CrashType::Timeout.is_memory_corruption());
        assert!(!CrashType::Abort.is_memory_corruption());
    }

    #[test]
    fn test_triage_from_signal() {
        assert_eq!(triage_from_signal(libc::SIGSEGV), CrashType::SegFault);
        assert_eq!(triage_from_signal(libc::SIGABRT), CrashType::Abort);
        assert_eq!(triage_from_signal(libc::SIGFPE), CrashType::FloatingPoint);
        assert_eq!(triage_from_signal(999), CrashType::Unknown);
    }

    #[test]
    fn test_triage_from_status() {
        assert_eq!(
            triage_from_status(&ExitStatus::Signal(libc::SIGSEGV)),
            CrashType::SegFault
        );
        assert_eq!(triage_from_status(&ExitStatus::Timeout), CrashType::Timeout);
        assert_eq!(
            triage_from_status(&ExitStatus::Normal(1)),
            CrashType::Unknown
        );
    }

    #[test]
    fn test_triage_from_asan() {
        assert_eq!(
            triage_from_asan("ERROR: AddressSanitizer: heap-buffer-overflow"),
            Some(CrashType::AsanHeapOverflow)
        );
        assert_eq!(
            triage_from_asan("ERROR: AddressSanitizer: stack-buffer-overflow"),
            Some(CrashType::AsanStackOverflow)
        );
        assert_eq!(
            triage_from_asan("ERROR: AddressSanitizer: heap-use-after-free"),
            Some(CrashType::AsanUseAfterFree)
        );
        assert_eq!(triage_from_asan("normal output"), None);
    }
}
