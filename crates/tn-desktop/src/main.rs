#![forbid(unsafe_code)]

//! Entrypoint for `tn-desktop`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tn_core::ai::LocalhostAiProvider;
use tn_desktop::DesktopServer;

fn main() {
    let port = 8080;
    println!("Starting TrustNotes Desktop Server on http://127.0.0.1:{port} ...");

    let ai_provider = match LocalhostAiProvider::new("http://127.0.0.1:11434/api/generate") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to initialize localhost AI provider: {e}");
            return;
        }
    };

    let server = match DesktopServer::start(port, None, ai_provider) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to start server: {e}");
            return;
        }
    };

    println!("============================================================");
    println!("TrustNotes Desktop Client is live at:");
    println!("  -> http://127.0.0.1:{}", server.port());
    println!("  -> Strict CSP: ENABLED (No remote CDN / zero tracking)");
    println!("  -> Zero-Knowledge Verification: ACTIVE");
    println!("  -> AI Boundary: LOCALHOST ONLY (Affirmative consent required)");
    println!("Press Ctrl+C to exit.");
    println!("============================================================");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Loop until terminated
    while r.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    server.stop();
}
