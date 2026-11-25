//! The 16-character backup code (`BackupCode::parse`): any text, no panic; an accepted code formats and
//! parses back to the same secret.
#![no_main]

use libfuzzer_sys::fuzz_target;
use regino_keys::backup_code::BackupCode;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(code) = BackupCode::parse(text) {
        let again = BackupCode::parse(&code.format()).expect("a formatted code parses");
        assert_eq!(again.as_bytes(), code.as_bytes());
    }
});
