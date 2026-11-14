//! Time of the Argon2id of a backup code: `cargo run --release -p regino-keys --example bench_backup_code`.
use regino_keys::backup_code::{self, BackupCode, DEFAULT_PARAMS, MAX_PARAMS};
use regino_keys::kdf::KdfParams;
use std::time::Instant;

fn main() {
    let code = BackupCode::generate().unwrap();
    let max = KdfParams { iterations: 2, ..MAX_PARAMS };
    for (label, p) in [("minimum", KdfParams::MIN), ("default", DEFAULT_PARAMS), ("128 MiB, 2 passes", max)] {
        let t = Instant::now();
        let n = 5;
        for _ in 0..n {
            backup_code::stretch(&code, &[7; 16], p).unwrap();
        }
        println!("{label:>18} (m = {} KiB, t = {}, p = {}): {:.0} ms", p.memory_kib, p.iterations, p.parallelism, t.elapsed().as_secs_f64() * 1000.0 / n as f64);
    }
}
