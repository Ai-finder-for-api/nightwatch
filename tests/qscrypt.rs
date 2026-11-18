use nightwatch::qscrypt::*;

#[test]
fn sha3_256_known_answer() {
    assert_eq!(
        sha3_256_hex(b"abc").unwrap(),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        sha3_256_hex(b"").unwrap(),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

#[test]
fn seal_open_roundtrip_and_tamper() {
    let k = Key::from_bytes(&nightwatch::platform::os_random(KEY_LEN).unwrap()).unwrap();
    let msg = br#"{"findings":[]}"#;
    let mut boxed = k.seal(msg).unwrap();
    assert_ne!(&boxed[..], &msg[..]);
    assert_eq!(k.open(&boxed).unwrap(), msg);
    let last = boxed.len() - 1;
    boxed[last] ^= 1;
    assert!(k.open(&boxed).is_err());
}

#[test]
fn wrong_key_and_bad_length_rejected() {
    let k1 = Key::generate().unwrap();
    let k2 = Key::generate().unwrap();
    let b = k1.seal(b"secret").unwrap();
    assert!(k2.open(&b).is_err());
    assert!(Key::from_bytes(&[1u8; 5]).is_err());
    assert!(k1.open(b"garbage").is_err());
}

#[test]
fn platform_paths() {
    assert!(nightwatch::platform::data_dir().ends_with("nightwatch"));
    assert_eq!(nightwatch::platform::os_random(16).unwrap().len(), 16);
}
