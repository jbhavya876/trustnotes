use std::process::Command;
use tn_core::search::SearchIndex;
use tn_types::Id16;

fn main() {
    let mut idx = SearchIndex::new();
    println!("Indexing 20,000 notes...");

    let start = std::time::Instant::now();
    for i in 0..20_000u32 {
        let mut id_bytes = [0u8; 16];
        id_bytes[0..4].copy_from_slice(&i.to_be_bytes());
        let id = Id16::from_bytes(id_bytes);

        let title = format!("Cryptographic Note #{i} - Zero Knowledge Transparency");
        let body = format!(
            "This is note {i} detailing Merkle tree invariants, post-quantum hybrid signatures, \
             and witness cosignatures. The epoch deadline ensures accountable promises across devices."
        );
        let tags = vec![
            "security".to_string(),
            format!("tag_{}", i % 50),
            "transparency".to_string(),
        ];

        idx.index_note(id, &title, &body, &tags);
    }
    let elapsed = start.elapsed();
    println!("Indexed 20,000 notes in {elapsed:?}");

    let pid = std::process::id();
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-Process -Id {pid}).WorkingSet64"),
        ])
        .output()
        .expect("failed to execute powershell");

    let mem_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let bytes: u64 = mem_str.parse().unwrap_or(0);
    let mb = bytes as f64 / (1024.0 * 1024.0);

    println!("Process Working Set: {mb:.2} MB (Target Ceiling: < 300 MB)");
    assert!(mb < 300.0, "Footprint {mb:.2} MB exceeds 300 MB limit!");

    // Verify search functionality on 20,000 notes
    let results = idx.search("transparency");
    println!("Search 'transparency' found {} notes", results.len());
    assert_eq!(results.len(), 20_000);
}
