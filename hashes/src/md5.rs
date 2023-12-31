use std::fmt::Display;
use std::fmt::Write;

#[rustfmt::skip]
const T: [u32; 65] = [
    // round 1
    0x00000000, 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    // round 2
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    // round 3
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    // round 4
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[inline(always)]
fn f(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, i: u32) -> u32 {
    // F(b, c, d) => X=b, Y=c, Z=d
    ((b & c) | (!b & d))
        .wrapping_add(a)
        .wrapping_add(k)
        .wrapping_add(i)
        .rotate_left(s)
        .wrapping_add(b)
}

#[inline(always)]
fn g(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, i: u32) -> u32 {
    // G(b, c, d) => X=b, Y=c, Z=d
    ((b & d) | (c & !d))
        .wrapping_add(a)
        .wrapping_add(k)
        .wrapping_add(i)
        .rotate_left(s)
        .wrapping_add(b)
}

#[inline(always)]
fn h(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, i: u32) -> u32 {
    // H(b, c, d) => X=b, Y=c, Z=d
    (b ^ c ^ d)
        .wrapping_add(a)
        .wrapping_add(k)
        .wrapping_add(i)
        .rotate_left(s)
        .wrapping_add(b)
}

#[inline(always)]
fn i(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, i: u32) -> u32 {
    // I(b, c, d) => X=b, Y=c, Z=d
    (c ^ (b | !d))
        .wrapping_add(a)
        .wrapping_add(k)
        .wrapping_add(i)
        .rotate_left(s)
        .wrapping_add(b)
}

pub struct MD5 {
    message: Vec<u8>,
    hash: [u32; 4],
}

// Implement Display trait to Sha1 struct
impl Display for MD5 {
    // fmtメソッドを定義
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Convert hash value to hexadecimal string
        // If not set to 08x, the leading 0 will disappear and 0x08ce5404 will not be displayed

        // Original code from my sha1.rs
        // md5 case need to change from b to b.swap_bytes() for little endian
        let hex = self.hash.iter().fold(String::new(), |mut acc, b| {
            write!(&mut acc, "{:08x}", b.swap_bytes()).unwrap();
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
pub trait MD5Digest {
    // type related to trait
    type Output;

    // const for 512bit block size
    const BLOCK_SIZE: usize = 64;
    // const for 160bit output
    const HASH_SIZE: usize = 16;

    fn new() -> Self;
    fn update(&mut self, input: &[u8]);
    fn finalize(self) -> Self::Output;
}

// Implement Sha1Digest trait to Sha1 struct
impl MD5Digest for MD5 {
    type Output = Self;

    // new method return the initialized Sha1 struct
    fn new() -> Self {
        Self {
            message: Vec::new(),
            hash: [
                0x6745_2301, // word A
                0xefcd_ab89, // word B
                0x98ba_dcfe, // word C
                0x1032_5476, // word D
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
        self.message.extend_from_slice(&len.to_le_bytes());

        // calc hash
        for chunk in self.message.chunks(Self::BLOCK_SIZE) {
            // div chuck to 16 - 32bit word
            let mut words = [0u32; 16];
            // A variable reference is obtained for the first 16 elements of words with take(16).
            for (i, word) in words.iter_mut().take(16).enumerate() {
                // each 4byte of chunk is converted to a 32-bit unsigned integer
                // word is a reference, so *word must be dereferenced
                // this is often done to change references to elements in the iterator
                *word = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
            }

            let mut a = self.hash[0]; // A
            let mut b = self.hash[1]; // B
            let mut c = self.hash[2]; // C
            let mut d = self.hash[3]; // D
            let aa = self.hash[0]; // A
            let bb = self.hash[1]; // B
            let cc = self.hash[2]; // C
            let dd = self.hash[3]; // D

            // round 1
            a = f(a, b, c, d, words[0], 7, T[1]);
            d = f(d, a, b, c, words[1], 12, T[2]);
            c = f(c, d, a, b, words[2], 17, T[3]);
            b = f(b, c, d, a, words[3], 22, T[4]);

            a = f(a, b, c, d, words[4], 7, T[5]);
            d = f(d, a, b, c, words[5], 12, T[6]);
            c = f(c, d, a, b, words[6], 17, T[7]);
            b = f(b, c, d, a, words[7], 22, T[8]);

            a = f(a, b, c, d, words[8], 7, T[9]);
            d = f(d, a, b, c, words[9], 12, T[10]);
            c = f(c, d, a, b, words[10], 17, T[11]);
            b = f(b, c, d, a, words[11], 22, T[12]);

            a = f(a, b, c, d, words[12], 7, T[13]);
            d = f(d, a, b, c, words[13], 12, T[14]);
            c = f(c, d, a, b, words[14], 17, T[15]);
            b = f(b, c, d, a, words[15], 22, T[16]);

            // round 2
            a = g(a, b, c, d, words[1], 5, T[17]);
            d = g(d, a, b, c, words[6], 9, T[18]);
            c = g(c, d, a, b, words[11], 14, T[19]);
            b = g(b, c, d, a, words[0], 20, T[20]);

            a = g(a, b, c, d, words[5], 5, T[21]);
            d = g(d, a, b, c, words[10], 9, T[22]);
            c = g(c, d, a, b, words[15], 14, T[23]);
            b = g(b, c, d, a, words[4], 20, T[24]);

            a = g(a, b, c, d, words[9], 5, T[25]);
            d = g(d, a, b, c, words[14], 9, T[26]);
            c = g(c, d, a, b, words[3], 14, T[27]);
            b = g(b, c, d, a, words[8], 20, T[28]);

            a = g(a, b, c, d, words[13], 5, T[29]);
            d = g(d, a, b, c, words[2], 9, T[30]);
            c = g(c, d, a, b, words[7], 14, T[31]);
            b = g(b, c, d, a, words[12], 20, T[32]);

            // round 3
            a = h(a, b, c, d, words[5], 4, T[33]);
            d = h(d, a, b, c, words[8], 11, T[34]);
            c = h(c, d, a, b, words[11], 16, T[35]);
            b = h(b, c, d, a, words[14], 23, T[36]);

            a = h(a, b, c, d, words[1], 4, T[37]);
            d = h(d, a, b, c, words[4], 11, T[38]);
            c = h(c, d, a, b, words[7], 16, T[39]);
            b = h(b, c, d, a, words[10], 23, T[40]);

            a = h(a, b, c, d, words[13], 4, T[41]);
            d = h(d, a, b, c, words[0], 11, T[42]);
            c = h(c, d, a, b, words[3], 16, T[43]);
            b = h(b, c, d, a, words[6], 23, T[44]);

            a = h(a, b, c, d, words[9], 4, T[45]);
            d = h(d, a, b, c, words[12], 11, T[46]);
            c = h(c, d, a, b, words[15], 16, T[47]);
            b = h(b, c, d, a, words[2], 23, T[48]);

            // round 4
            a = i(a, b, c, d, words[0], 6, T[49]);
            d = i(d, a, b, c, words[7], 10, T[50]);
            c = i(c, d, a, b, words[14], 15, T[51]);
            b = i(b, c, d, a, words[5], 21, T[52]);

            a = i(a, b, c, d, words[12], 6, T[53]);
            d = i(d, a, b, c, words[3], 10, T[54]);
            c = i(c, d, a, b, words[10], 15, T[55]);
            b = i(b, c, d, a, words[1], 21, T[56]);

            a = i(a, b, c, d, words[8], 6, T[57]);
            d = i(d, a, b, c, words[15], 10, T[58]);
            c = i(c, d, a, b, words[6], 15, T[59]);
            b = i(b, c, d, a, words[13], 21, T[60]);

            a = i(a, b, c, d, words[4], 6, T[61]);
            d = i(d, a, b, c, words[11], 10, T[62]);
            c = i(c, d, a, b, words[2], 15, T[63]);
            b = i(b, c, d, a, words[9], 21, T[64]);

            // refresh hash
            self.hash[0] = a.wrapping_add(aa);
            self.hash[1] = b.wrapping_add(bb);
            self.hash[2] = c.wrapping_add(cc);
            self.hash[3] = d.wrapping_add(dd);
        }
        // return Sha1 struct
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::md5::MD5Digest;

    #[test]
    fn test_1() {
        let message: &[u8] = "Hello".as_bytes();
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(message);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("8b1a9953c4611296a827abf8c47804d7", result);
    }

    #[test]
    fn test_2() {
        // let message: &[u8] = "Hello !".as_bytes();
        let input = b"a";
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(input);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("0cc175b9c0f1b6a831c399e269772661", result);
    }

    #[test]
    fn test_3() {
        let message: &[u8] = "".as_bytes();
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(message);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("d41d8cd98f00b204e9800998ecf8427e", result);
    }

    #[test]
    fn test_4() {
        let input = b"abc";
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(input);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("900150983cd24fb0d6963f7d28e17f72", result);
    }

    #[test]
    fn test_5() {
        let input = b"message digest";
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(input);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("f96b697d7cb7938d525a2f31aaf161d0", result);
    }

    #[test]
    fn test_6() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(input);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("c3fcd3d76192e4007dfb496cca67e13b", result);
    }

    #[test]
    fn test_7() {
        let input = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(input);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("d174ab98d277d9f5a5611c2c9f419d9f", result);
    }

    #[test]
    fn test_8() {
        let input =
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        let mut hashtest = crate::md5::MD5::new();
        hashtest.update(input);
        let hashtest = hashtest.finalize();
        let result = format!("{}", hashtest);
        println!("{}", result);

        assert_eq!("57edf4a22be3c955ac49da2e2107b67a", result);
    }
}
