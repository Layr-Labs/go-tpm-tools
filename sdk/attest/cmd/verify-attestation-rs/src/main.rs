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
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    let tmp_path = std::env::temp_dir()
        .join(format!("verify-attest-{}.json", std::process::id()));

    let mut cmd = Command::new(binary);
    cmd.arg("-output").arg(&tmp_path)
        .arg(attestation_b64).arg(challenge_hex);
    if !extra_data_hex.is_empty() {
        cmd.arg(extra_data_hex);
    }
    // Discard stdout entirely — JSON goes to the output file.
    // Capture stderr so we can surface it on failure.
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());

    let output = cmd.output().map_err(|e| format!("failed to run verify-attestation: {e}"))?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&tmp_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("verify-attestation exited {}: {}", output.status, stderr.trim()));
    }

    // Read before deleting; delete unconditionally so a read error doesn't leak the file.
    let json_result = std::fs::read_to_string(&tmp_path)
        .map_err(|e| format!("read output file: {e}"));
    let _ = std::fs::remove_file(&tmp_path);
    let json = json_result?;

    serde_json::from_str(&json).map_err(|e| format!("failed to parse JSON output: {e}"))
}

fn format_claims(name: &str, result: &VerifyOutput) -> String {
    let mut out = String::new();
    writeln!(out, "  TPM claims:").unwrap();
    if let Some(tpm) = &result.tpm_claims {
        writeln!(out, "    platform: {}", tpm.platform).unwrap();
        writeln!(out, "    hardened: {}", tpm.hardened).unwrap();
        writeln!(out, "    pcrs:     {} entries", tpm.pcrs.len()).unwrap();
        if let Some(gce) = &tpm.gce {
            writeln!(out, "    gce:      project={} zone={} instance={}",
                gce.project_id, gce.zone, gce.instance_name).unwrap();
        }
    }
    writeln!(out, "  TEE claims:").unwrap();
    if let Some(tee) = &result.tee_claims {
        writeln!(out, "    platform: {}", tee.platform).unwrap();
        if let Some(tdx) = &tee.tdx {
            writeln!(out, "    TDX mrtd:  {}...", &tdx.mrtd[..16]).unwrap();
            writeln!(out, "    debug:     {}", tdx.attributes.debug).unwrap();
        }
        if let Some(snp) = &tee.sevsnp {
            writeln!(out, "    SEV-SNP measurement: {}...", &snp.measurement[..16]).unwrap();
            writeln!(out, "    debug:               {}", snp.policy.debug).unwrap();
        }
    } else {
        writeln!(out, "    (none — Shielded VM)").unwrap();
    }
    writeln!(out, "  Container claims:").unwrap();
    if let Some(c) = &result.container_claims {
        writeln!(out, "    image: {}", c.image_reference).unwrap();
        writeln!(out, "    digest: {}", c.image_digest).unwrap();
        writeln!(out, "    args: {:?}", c.args).unwrap();
    } else {
        writeln!(out, "    (none)").unwrap();
    }
    let is_debug = result
        .tee_claims
        .as_ref()
        .map(|tee| {
            tee.tdx.as_ref().map_or(false, |t| t.attributes.debug)
                || tee.sevsnp.as_ref().map_or(false, |s| s.policy.debug)
        })
        .unwrap_or(false);
    let is_hardened = result.tpm_claims.as_ref().map_or(false, |t| t.hardened);
    if is_debug {
        writeln!(out, "  CHECK: REJECTED — debug TEE attestation for {name}").unwrap();
    } else if !is_hardened {
        writeln!(out, "  CHECK: WARNING — not hardened for {name}").unwrap();
    } else {
        writeln!(out, "  CHECK: OK — hardened, non-debug attestation for {name}").unwrap();
    }
    out
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
            Ok(result) => print!("{}", format_claims("input", &result)),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("usage: verify-attestation-rs <attestation_b64> <challenge_hex> [extra_data_hex]\n\
                          verify-attestation-rs --test-vectors <attestations.json>");
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

    let total = vectors.len();
    let mut passed = 0usize;
    let mut failed = 0usize;

    for v in &vectors {
        println!("--- {} ---", v.name);
        match verify_attestation(binary, &v.attestation, &v.challenge, &v.extra_data) {
            Ok(result) => {
                print!("{}", format_claims(&v.name, &result));
                let tpm = result.tpm_claims.as_ref().expect("tpm_claims should exist");
                if tpm.platform.to_ascii_uppercase() != v.platform.to_ascii_uppercase() {
                    println!("  FAIL: platform mismatch: got {}, want {}", tpm.platform, v.platform);
                    failed += 1;
                } else if tpm.hardened != v.hardened {
                    println!("  FAIL: hardened mismatch: got {}, want {}", tpm.hardened, v.hardened);
                    failed += 1;
                } else {
                    passed += 1;
                }
            }
            Err(e) => {
                println!("  FAIL: {e}");
                failed += 1;
            }
        }
        println!();
    }

    println!("=== {passed} passed, {failed} failed out of {total} vectors ===");
    if failed > 0 {
        std::process::exit(1);
    }
}
