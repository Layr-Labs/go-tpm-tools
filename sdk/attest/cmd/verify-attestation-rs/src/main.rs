//! Example: call the `verify-attestation` Go binary as a subprocess
//! and deserialize + inspect the resulting claims.
//!
//! Usage:
//!   # Verify a single attestation:
//!   cargo run -- <attestation_b64> <challenge_hex> [extra_data_hex]
//!
//!   # Run against all test vectors in attestations.json:
//!   cargo run -- --test-vectors ../../testdata/attestations.json

#![allow(dead_code)] // Fields deserialized but not all individually inspected.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// JSON types matching verify-attestation output
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct VerifyOutput {
    tpm_claims: Option<TpmClaims>,
    tee_claims: Option<TeeClaims>,
    container_claims: Option<ContainerClaims>,
}

#[derive(Debug, Deserialize)]
struct TpmClaims {
    platform: String,
    hardened: bool,
    pcrs: HashMap<String, String>,
    gce: Option<GceInfo>,
}

#[derive(Debug, Deserialize)]
struct GceInfo {
    project_id: String,
    project_number: String,
    zone: String,
    instance_id: String,
    instance_name: String,
}

#[derive(Debug, Deserialize)]
struct TeeClaims {
    platform: String,
    tdx: Option<TdxClaims>,
    sevsnp: Option<SevSnpClaims>,
}

#[derive(Debug, Deserialize)]
struct TdxClaims {
    mrtd: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
    tee_tcb_svn: String,
    attributes: TdAttributes,
}

#[derive(Debug, Deserialize)]
struct TdAttributes {
    debug: bool,
    sept_ve_disable: bool,
    pks: bool,
    kl: bool,
    perf_mon: bool,
}

#[derive(Debug, Deserialize)]
struct SevSnpClaims {
    measurement: String,
    host_data: String,
    current_tcb: String,
    reported_tcb: String,
    committed_tcb: String,
    guest_svn: u32,
    policy: SevSnpPolicy,
}

#[derive(Debug, Deserialize)]
struct SevSnpPolicy {
    debug: bool,
    migrate_ma: bool,
    smt: bool,
    abi_minor: u8,
    abi_major: u8,
    single_socket: bool,
    ciphertext_hiding_dram: bool,
}

#[derive(Debug, Deserialize)]
struct ContainerClaims {
    image_reference: String,
    image_digest: String,
    image_id: String,
    restart_policy: String,
    args: Vec<String>,
    env_vars: HashMap<String, String>,
}

// Test vector format (matches attestations.json)
#[derive(Debug, Deserialize)]
struct TestVector {
    name: String,
    platform: String,
    hardened: bool,
    attestation: String, // base64
    challenge: String,   // hex
    extra_data: String,  // hex
}

// ---------------------------------------------------------------------------
// Core: call the Go binary and parse output
// ---------------------------------------------------------------------------

fn verify_attestation(
    binary: &Path,
    attestation_b64: &str,
    challenge_hex: &str,
    extra_data_hex: &str,
) -> Result<VerifyOutput, String> {
    let mut cmd = Command::new(binary);
    cmd.arg(attestation_b64).arg(challenge_hex);
    if !extra_data_hex.is_empty() {
        cmd.arg(extra_data_hex);
    }

    let output = cmd.output().map_err(|e| format!("failed to run verify-attestation: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "verify-attestation exited {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("invalid utf-8 in stdout: {e}"))?;

    // The Go TDX verification library may write warnings directly to fd 1,
    // bypassing Go's os.Stdout. Strip any non-JSON prefix by finding the
    // first '{' character.
    let json_start = stdout
        .find('{')
        .ok_or_else(|| format!("no JSON object in stdout (got: {:?})", &stdout[..stdout.len().min(200)]))?;

    serde_json::from_str(&stdout[json_start..])
        .map_err(|e| format!("failed to parse JSON output: {e}"))
}

fn print_claims(name: &str, result: &VerifyOutput) {
    println!("  TPM claims:");
    if let Some(tpm) = &result.tpm_claims {
        println!("    platform: {}", tpm.platform);
        println!("    hardened: {}", tpm.hardened);
        println!("    pcrs:     {} entries", tpm.pcrs.len());
        if let Some(gce) = &tpm.gce {
            println!("    gce:      project={} zone={} instance={}", gce.project_id, gce.zone, gce.instance_name);
        }
    }

    println!("  TEE claims:");
    if let Some(tee) = &result.tee_claims {
        println!("    platform: {}", tee.platform);
        if let Some(tdx) = &tee.tdx {
            println!("    TDX mrtd:  {}...", &tdx.mrtd[..16]);
            println!("    debug:     {}", tdx.attributes.debug);
        }
        if let Some(snp) = &tee.sevsnp {
            println!("    SEV-SNP measurement: {}...", &snp.measurement[..16]);
            println!("    debug:               {}", snp.policy.debug);
        }
    } else {
        println!("    (none — Shielded VM)");
    }

    println!("  Container claims:");
    if let Some(c) = &result.container_claims {
        println!("    image: {}", c.image_reference);
        println!("    digest: {}", c.image_digest);
        println!("    args: {:?}", c.args);
    } else {
        println!("    (none)");
    }

    // Example check: reject debug attestations.
    let is_debug = result
        .tee_claims
        .as_ref()
        .map(|tee| {
            tee.tdx.as_ref().map_or(false, |t| t.attributes.debug)
                || tee.sevsnp.as_ref().map_or(false, |s| s.policy.debug)
        })
        .unwrap_or(false);
    let is_hardened = result
        .tpm_claims
        .as_ref()
        .map_or(false, |t| t.hardened);

    if is_debug {
        println!("  CHECK: REJECTED — debug TEE attestation for {name}");
    } else if !is_hardened {
        println!("  CHECK: WARNING — not hardened for {name}");
    } else {
        println!("  CHECK: OK — hardened, non-debug attestation for {name}");
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Resolve the Go binary — look next to ourselves, then in PATH.
    let binary = find_binary().unwrap_or_else(|| PathBuf::from("verify-attestation"));

    if args.len() >= 3 && args[1] == "--test-vectors" {
        // Run against all test vectors from attestations.json.
        run_test_vectors(&binary, &args[2]);
    } else if args.len() >= 3 {
        // Single attestation: <attestation_b64> <challenge_hex> [extra_data_hex]
        let extra = args.get(3).map(|s| s.as_str()).unwrap_or("");
        match verify_attestation(&binary, &args[1], &args[2], extra) {
            Ok(result) => {
                print_claims("input", &result);
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!(
            "usage: verify-attestation-rs <attestation_b64> <challenge_hex> [extra_data_hex]"
        );
        eprintln!(
            "       verify-attestation-rs --test-vectors <attestations.json>"
        );
        std::process::exit(1);
    }
}

fn find_binary() -> Option<PathBuf> {
    // VERIFY_ATTESTATION_BIN env var takes priority.
    if let Ok(p) = std::env::var("VERIFY_ATTESTATION_BIN") {
        return Some(PathBuf::from(p));
    }
    // Check next to this executable (e.g. both built into same dir).
    if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent()?;
        let candidate = dir.join("verify-attestation");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    // Check current working directory. Use "./" prefix so Command::new
    // executes from cwd rather than searching PATH.
    let cwd = PathBuf::from("./verify-attestation");
    if cwd.exists() {
        return Some(cwd);
    }
    None
}

fn run_test_vectors(binary: &Path, path: &str) {
    let data = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });
    let vectors: Vec<TestVector> = serde_json::from_str(&data).unwrap_or_else(|e| {
        eprintln!("failed to parse {path}: {e}");
        std::process::exit(1);
    });

    let mut passed = 0;
    let mut failed = 0;

    for v in &vectors {
        println!("--- {} ---", v.name);
        match verify_attestation(binary, &v.attestation, &v.challenge, &v.extra_data) {
            Ok(result) => {
                print_claims(&v.name, &result);
                // Sanity checks.
                let tpm = result.tpm_claims.as_ref().expect("tpm_claims should exist");
                assert_eq!(
                    tpm.platform.to_ascii_uppercase(),
                    v.platform.to_ascii_uppercase(),
                    "platform mismatch"
                );
                assert_eq!(tpm.hardened, v.hardened, "hardened mismatch");
                passed += 1;
            }
            Err(e) => {
                eprintln!("  FAIL: {e}");
                failed += 1;
            }
        }
        println!();
    }

    println!("=== {passed} passed, {failed} failed out of {} vectors ===", vectors.len());
    if failed > 0 {
        std::process::exit(1);
    }
}
