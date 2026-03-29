//! Integration tests using test targets.
//!
//! These tests require the test_targets to be compiled first:
//! cd test_targets && make all

use fuzz::executor::{ExitStatus, ForkExecutor, InputMode};
use std::path::PathBuf;
use std::time::Duration;

fn target_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_targets")
        .join(name)
}

fn target_exists(name: &str) -> bool {
    target_path(name).exists()
}

#[test]
fn test_null_deref_normal_input() {
    if !target_exists("null_deref") {
        eprintln!("Skipping: null_deref not compiled. Run `cd test_targets && make`");
        return;
    }

    let executor = ForkExecutor::new(target_path("null_deref"))
        .timeout(Duration::from_secs(1))
        .input_mode(InputMode::Stdin);

    // Normal input - should not crash
    let result = executor.run(b"hello").unwrap();
    assert!(matches!(result.status, ExitStatus::Normal(0)));
}

#[test]
fn test_null_deref_crash() {
    if !target_exists("null_deref") {
        eprintln!("Skipping: null_deref not compiled. Run `cd test_targets && make`");
        return;
    }

    let executor = ForkExecutor::new(target_path("null_deref"))
        .timeout(Duration::from_secs(1))
        .input_mode(InputMode::Stdin);

    // Magic sequence - should crash
    let result = executor.run(b"ABC").unwrap();
    assert!(
        matches!(result.status, ExitStatus::Signal(_)),
        "Expected signal, got {:?}",
        result.status
    );
}

#[test]
fn test_timeout_normal_input() {
    if !target_exists("timeout") {
        eprintln!("Skipping: timeout not compiled. Run `cd test_targets && make`");
        return;
    }

    let executor = ForkExecutor::new(target_path("timeout"))
        .timeout(Duration::from_millis(500))
        .input_mode(InputMode::Stdin);

    // Normal input - should complete (not timeout)
    let result = executor.run(b"hello").unwrap();
    assert!(
        matches!(result.status, ExitStatus::Normal(_)),
        "Expected normal exit, got {:?}",
        result.status
    );
}

#[test]
fn test_timeout_hang() {
    if !target_exists("timeout") {
        eprintln!("Skipping: timeout not compiled. Run `cd test_targets && make`");
        return;
    }

    let executor = ForkExecutor::new(target_path("timeout"))
        .timeout(Duration::from_millis(100))
        .input_mode(InputMode::Stdin);

    // Magic byte - should timeout
    let result = executor.run(b"X").unwrap();
    assert!(
        matches!(result.status, ExitStatus::Timeout),
        "Expected timeout, got {:?}",
        result.status
    );
}

#[test]
fn test_deep_crash_partial() {
    if !target_exists("deep_crash") {
        eprintln!("Skipping: deep_crash not compiled. Run `cd test_targets && make`");
        return;
    }

    let executor = ForkExecutor::new(target_path("deep_crash"))
        .timeout(Duration::from_secs(1))
        .input_mode(InputMode::Stdin);

    // Partial magic - should not crash
    let result = executor.run(b"FUZ").unwrap();
    assert!(matches!(result.status, ExitStatus::Normal(0)));
}

#[test]
fn test_deep_crash_full() {
    if !target_exists("deep_crash") {
        eprintln!("Skipping: deep_crash not compiled. Run `cd test_targets && make`");
        return;
    }

    let executor = ForkExecutor::new(target_path("deep_crash"))
        .timeout(Duration::from_secs(1))
        .input_mode(InputMode::Stdin);

    // Full magic sequence - should crash
    let result = executor.run(b"FUZZME").unwrap();
    assert!(
        matches!(result.status, ExitStatus::Signal(_)),
        "Expected signal, got {:?}",
        result.status
    );
}
