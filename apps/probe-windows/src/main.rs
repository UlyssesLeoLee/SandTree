//! Probe entry point.
//!
//! Deliberately tiny: parse two arguments, collect, publish, exit. There is no
//! mode that runs a caller-supplied command, because that is the capability
//! NFR-S07 refuses to grant the probe in the first place.

use std::process::ExitCode;

use sandtree_probe_windows::{collect, now_rfc3339, Envelope, Outbox};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let sandbox_id = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("usage: probe-windows <sandbox-id> <outbox-dir> [run-id] [nonce]");
            return ExitCode::from(2);
        }
    };
    let outbox_dir = match args.next() {
        Some(v) => v,
        None => {
            eprintln!("usage: probe-windows <sandbox-id> <outbox-dir> [run-id] [nonce]");
            return ExitCode::from(2);
        }
    };
    let run_id = args.next().unwrap_or_else(|| default_run_id(&sandbox_id));
    let nonce = args
        .next()
        .unwrap_or_else(|| "host-supplied-nonce-placeholder".to_string());

    let outbox = match Outbox::open(&outbox_dir) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("probe-windows: cannot open outbox {outbox_dir}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let envelope = Envelope::new(
        sandbox_id.clone(),
        nonce,
        1,
        now_rfc3339(),
        collect(&sandbox_id),
    );

    match outbox.publish(&run_id, &envelope) {
        Ok(path) => {
            println!("{} {}", path.display(), envelope.payload_hash);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("probe-windows: publication failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A run id that is unique per sandbox and needs no random source: the host
/// matches on the nonce, and the file name only has to avoid collisions within
/// one sandbox.
fn default_run_id(sandbox_id: &str) -> String {
    let sanitized: String = sandbox_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{sanitized}-probe")
}
