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
