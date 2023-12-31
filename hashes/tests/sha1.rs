extern crate hashes;
use hashes::sha1;
use hashes::sha1::Sha1Digest;

mod common;

#[test]
fn sha1_hello() {
    let message: &[u8] = "Hello".as_bytes();
    let mut hashtest = sha1::Sha1::new();
    hashtest.update(message);
    let hashtest = hashtest.finalize();
    let result = format!("{}", hashtest);
    println!("{}", result);

    assert_eq!("f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0", result);
}

#[test]
fn sha1_hello_world() {
    let input = b"Hello World!";
    let mut hashtest = sha1::Sha1::new();
    hashtest.update(input);
    let hashtest = hashtest.finalize();
    let result = format!("{}", hashtest);
    println!("{}", result);

    assert_eq!("2ef7bde608ce5404e97d5f042f95f89f1c232871", result);
}

#[test]
fn sha1_blank() {
    let message: &[u8] = "".as_bytes();
    let mut hashtest = sha1::Sha1::new();
    hashtest.update(message);
    let hashtest = hashtest.finalize();
    let result = format!("{}", hashtest);
    println!("{}", result);

    assert_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", result);
}

#[test]
fn sha1_3block_long() {
    let message: &[u8] = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3".as_bytes();
    let mut hashtest = sha1::Sha1::new();
    hashtest.update(message);
    let hashtest = hashtest.finalize();
    let result = format!("{}", hashtest);
    println!("{}", result);

    assert_eq!("3400932512e8e8fc2b51c9d8784dffbe1495b449", result);
}
