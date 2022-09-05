use std::str::FromStr;
use std::{fmt::Write, num::ParseIntError};

use ::sha256;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::util::base58::check_encode_slice;
use rand::Rng;
use secp256k1::{Secp256k1, SecretKey};

// Helpful articles:
// - http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
// - https://en.bitcoin.it/wiki/Base58Check_encoding
// - https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
// - https://gobittest.appspot.com/Address
// - https://en.bitcoin.it/wiki/Protocol_documentation#Signatures
//

pub fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

// Source: https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

// Source: https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn create_private_key() -> String {
    // we create an array that will store the byte representation of each of our numbers. We're
    //   going to have 64 numbers, so the length will be 64, where each item represents a 16 byte
    //   number (0 -15).
    let mut byte_array: Vec<u8> = Vec::new();
    // we create an string that will represent our byte_array but as a hexidecimal number
    // let mut s = String::new();
    // loop through 64 times and create a new hex number each time because
    //    we want a number with 64 digits, and each of them will be 4 bytes,
    //    for a number with 256 bytes total.
    for _x in 0..64 {
        // get number between 0 - 255 billion;
        let mut rng = rand::thread_rng();
        let random_int_1 = rng.gen_range(0..255);
        // get number between 1 - 16;
        let random_int_2 = rng.gen_range(1..=16);

        // we dont want a number any larger than 15 (because we want a 4 byte number)
        //    so we have to modulo our first random number by our second. Notice the second
        //    random number can only go as high as 16 and by moduloing our random number by that
        //    we'll never get a number larger than 16
        let random_num = random_int_1 % random_int_2;
        // push our random number onto the byte array
        byte_array.push(random_num);
        // push our random number onto the string
        // let hex = format!("{:x}", b);
        //s.push_str(&hex);
    }

    // convert byte array into a hex string
    let s = byte_array
        .iter()
        .map(|byte| format!("{:x}", byte))
        .collect::<String>();
    s
}

fn get_uncompressed_public_key_from_private_key(private_key: &str) -> String {
    // Create 512 bit public key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(private_key).unwrap();
    // We're getting the OLDER uncompressed version of the public key:
    //    Source: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    let public_key_uncompressed = secret_key.public_key(&secp).serialize_uncompressed();
    encode_hex(&public_key_uncompressed)
}

// https://en.bitcoin.it/wiki/Wallet_import_format
fn get_wif_private_key(private_key: &String, is_testnet: bool) -> String {
    // 0x80 is used for the version/application byte
    // https://river.com/learn/terms/w/wallet-import-format-wif/#:~:text=WIF%20format%20adds%20a%20prefix,should%20use%20compressed%20SEC%20format.
    let version_application_byte_for_mainnet = "80";
    let version_application_byte_for_testnet = "ef";

    let version_application_byte = if is_testnet {
        version_application_byte_for_testnet
    } else {
        version_application_byte_for_mainnet
    };
    let private_key_hex = decode_hex(&private_key).unwrap();
    let version_array = decode_hex(version_application_byte_for_testnet).unwrap();
    // What does check encodings do?
    //   - does a sha25 twice, then gets the first 4 bytes of that Result
    //   - takes those first four bites and appends them to the original (version + hex array)
    //   - Read "Ecoding a private key" section here: https://en.bitcoin.it/wiki/Base58Check_encoding
    let combined_version_and_private_key_hex = concat_u8(&version_array, &private_key_hex);
    let wif_private_key = check_encode_slice(&combined_version_and_private_key_hex);
    wif_private_key
}
fn get_public_key_hash(public_key: &String) -> String {
    let hex_array = decode_hex(public_key).unwrap();
    let public_key_sha256 = sha256::digest_bytes(&hex_array);
    let public_key_sha256_as_hex_array = decode_hex(&public_key_sha256).unwrap();
    let public_key_ripemd160 = ripemd160::Hash::hash(&public_key_sha256_as_hex_array);
    public_key_ripemd160.to_string()
}

// This is for p2pkh. P2sh requires us to get address from redeem script:
//      Source: https://en.bitcoin.it/wiki/Base58Check_encoding
fn get_address_from_pub_key_hash(public_key_hash: &String, is_testnet: bool) -> String {
    // SEE ALL VERSION APPLICATION CODES HERE: https://en.bitcoin.it/wiki/List_of_address_prefixes
    let p2pkh_version_application_byte = "00";
    let p2pkh_testnet_version_application_byte = "6f";
    let p2sh_version_application_byte = "05";

    let version_application_byte = if is_testnet {
        p2pkh_testnet_version_application_byte
    } else {
        p2pkh_version_application_byte
    };
    let hex_array = Vec::from_hex(public_key_hash).unwrap();
    let version_array = decode_hex(version_application_byte).unwrap();
    let a = concat_u8(&version_array, &hex_array);
    // What does check encodings do?
    //   - does a sha25 twice, then gets the first 4 bytes of that Result
    //   - takes those first four bites and appends them to the original (version + hex array)
    //   - Read "Encoding a bitcoin address": https://en.bitcoin.it/wiki/Base58Check_encoding
    let address = check_encode_slice(&a);
    address
}

fn main() {
    let is_testnet = true;
    let private_key = create_private_key();
    println!("private key: {}", &private_key);
    let public_key = get_uncompressed_public_key_from_private_key(&private_key);
    println!("public_key {}", public_key);
    let wif_private_key = get_wif_private_key(&private_key, is_testnet);
    println!("wif_private_key: {}", wif_private_key);
    let public_key_hash = get_public_key_hash(&public_key);
    println!("public_key_hash: {}", public_key_hash);
    let address = get_address_from_pub_key_hash(&public_key_hash, is_testnet);
    println!("address: {}", address);
    // println!("{}", private_key.bytes().len());
    // println!("{}", private_key)
}
