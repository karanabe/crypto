use std::fmt::Display;
use std::fmt::Write;

pub struct Sha1 {
    message: Vec<u8>,
    hash: [u32; 5],
}

// Implement Display trait to Sha1 struct
impl Display for Sha1 {
    // fmtメソッドを定義
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Convert hash value to hexadecimal string
        // If not set to 08x, the leading 0 will disappear and 0x08ce5404 will not be displayed
        let hex = self.hash.iter().fold(String::new(), |mut acc, b| {
            write!(&mut acc, "{:08x}", b).unwrap();
            acc
        });

        /*
        The original code is shown below, but it gives a clippy error `use of `format!` to build up a string from an iterator`.
        Using the `format!` macro to build up a string from an iterator results in poor performance.
        This is because using the format! macro causes memory allocation and freeing.
        So, when you make strings from iterators, use fold function and write! macro instead of format! macro to improve performance.
        ```rust
        let hex = self
            .hash
            .iter()
            .map(|b| format!("{:08x}", b))
            .collect::<String>();
        ```
        */
        // Write to formatter
        write!(f, "{}", hex)
    }
}

// Sha1Digest calculate sha1 hash
pub trait Sha1Digest {
    // type related to trait
    type Output;

    // const for 512bit block size
    const BLOCK_SIZE: usize = 64;
    // const for 160bit output
    const HASH_SIZE: usize = 20;

    fn new() -> Self;
    fn update(&mut self, input: &[u8]);
    fn finalize(self) -> Self::Output;
}

// Implement Sha1Digest trait to Sha1 struct
impl Sha1Digest for Sha1 {
    type Output = Self;

    // new method return the initialized Sha1 struct
    fn new() -> Self {
        Self {
            message: Vec::new(),
            hash: [
                0x67452301, // h0
                0xefcdab89, // h1
                0x98badcfe, // h2
                0x10325476, // h3
                0xc3d2e1f0, // h4
            ],
        }
    }

    // update method add input message
    fn update(&mut self, input: &[u8]) {
        self.message.extend_from_slice(input);
    }
    // finalize method do padding and calculate sha1 hash
    fn finalize(mut self) -> Self::Output {
        // Padding processing
        // 1 byte = 8 bits, Hello = 5 bytes = (5 * 8) bits = 40 bits
        // message length (in bits)
        // Add 8bit/1byte 0x80 to the end of the message 0x80 = 10000000
        // add 0x80 to the end of the message 0x80 = 10000000
        // message length comes from 8-bit units.
        // Add 1 bit of 1 and 0 for the remaining 7 bits because we don't think there is any room in the last byte of the message.
        // This is the reason for 0x80.
        let len = (self.message.len() * 8) as u64;
        // Add 1 bit of 1
        self.message.push(0x80);
        // +8 here will be 8 bytes = 64 bits to add the last message length.
        // Padding is done until mod 512 becomes 0.
        // This code itself is designed to handle more than 447 bits.
        // 512 -> 512 - 64 -> 448 -1 -> 447bit => this 447 is the longest in the last block.
        // In fact, even if you are not aware of this kind of thing, the following code is used to express it.
        while (self.message.len() + 8) % Self::BLOCK_SIZE != 0 {
            // add 0 bit
            self.message.push(0x00);
        }
        // add 64bit message length
        self.message.extend_from_slice(&len.to_be_bytes());

        // calc hash
        for chunk in self.message.chunks(Self::BLOCK_SIZE) {
            // div chuck to 16 - 31bit word
            let mut words = [0u32; 80];
            // A variable reference is obtained for the first 16 elements of words with take(16).
            for (i, word) in words.iter_mut().take(16).enumerate() {
                // each 4byte of chunk is converted to a 32-bit unsigned integer
                // word is a reference, so *word must be dereferenced
                // this is often done to change references to elements in the iterator
                *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
            }

            // Expand to 80 32-bit words
            for i in 16..80 {
                let temp = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
                words[i] = temp.rotate_left(1);
            }

            let mut a = self.hash[0];
            let mut b = self.hash[1];
            let mut c = self.hash[2];
            let mut d = self.hash[3];
            let mut e = self.hash[4];

            // main loop
            for (i, _item) in words.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                    20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                    60..=79 => (b ^ c ^ d, 0xca62_c1d6),
                    _ => unreachable!(),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(words[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            // refresh hash
            self.hash[0] = self.hash[0].wrapping_add(a);
            self.hash[1] = self.hash[1].wrapping_add(b);
            self.hash[2] = self.hash[2].wrapping_add(c);
            self.hash[3] = self.hash[3].wrapping_add(d);
            self.hash[4] = self.hash[4].wrapping_add(e);
        }
        // return Sha1 struct
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::sha1::Sha1Digest;

    #[test]
    fn test_1() {
        let message: &[u8] = "Hello".as_bytes();
        let mut hashtest = crate::sha1::Sha1::new();
        hashtest.update(message);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0", result);
    }

    #[test]
    fn test_2() {
        // let message: &[u8] = "Hello !".as_bytes();
        let input = b"Hello World!";
        let mut hashtest = crate::sha1::Sha1::new();
        hashtest.update(input);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("2ef7bde608ce5404e97d5f042f95f89f1c232871", result);
    }

    #[test]
    fn test_3() {
        let message: &[u8] = "".as_bytes();
        let mut hashtest = crate::sha1::Sha1::new();
        hashtest.update(message);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("da39a3ee5e6b4b0d3255bfef95601890afd80709", result);
    }
}
