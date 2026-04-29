// build.rs — generate cross-language test vectors before compilation.
//
// Runs `go test -run TestGenerateVectors ./pkg/protocol` from the repo root so
// that testdata/vectors/*.json exist for the integration tests in
// tests/protocol_vectors.rs.
//
// If `go` is not on PATH the step is skipped with a warning; the Rust tests
// will still compile and will report a skip rather than a hard failure.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // clients/rust/ -> repo root
    let repo_root = PathBuf::from(&manifest_dir).join("../..");

    let status = Command::new("go")
        .args(["test", "-run", "TestGenerateVectors", "./pkg/protocol"])
        .current_dir(&repo_root)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "cargo:warning=test vector generator exited with {:?}",
            s.code()
        ),
        Err(e) => eprintln!(
            "cargo:warning=could not run go test vector generator (is `go` on PATH?): {e}"
        ),
    }

    // Re-run build.rs only when the Go protocol package or the vector dir changes.
    println!("cargo:rerun-if-changed=../../pkg/protocol/");
    println!("cargo:rerun-if-changed=../../testdata/vectors/");
}
