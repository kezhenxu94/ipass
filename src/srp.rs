use num::{BigInt, Num};

use num_bigint::Sign;
use sha2::{Digest, Sha256};

pub fn pad(data: &[u8], len: usize) -> Vec<u8> {
    let mut padded = vec![0; len];
    padded[len - data.len()..].copy_from_slice(data);
    padded
}

pub fn pre_master_secret(
    client_public_key: &Vec<u8>,
    client_private_key: &[u8],
    server_public_key: &Vec<u8>,
    username: &String,
    password: &String,
    salt: &Vec<u8>,
) -> Vec<u8> {
    let group_prime = BigInt::from_str_radix( r#"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"#, 16).unwrap();
    let group_generator = BigInt::from_bytes_be(num_bigint::Sign::Plus, &[5]);

    let padded_client_pub = pad(client_public_key.as_slice(), 3072 >> 3);
    let padded_server_pub = pad(server_public_key.as_slice(), 3072 >> 3);

    let mut hasher = Sha256::new();
    hasher.update([padded_client_pub.as_slice(), padded_server_pub.as_slice()].concat());
    let u = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(group_prime.to_bytes_be().1);
    let padded_generator = pad(group_generator.to_bytes_be().1.as_slice(), 3072 >> 3);
    hasher.update(&padded_generator);
    let k = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", username, password).as_bytes());
    let hash = hasher.finalize().to_vec();

    let salted = [salt.as_slice(), hash.as_slice()].concat();

    let mut hasher = Sha256::new();
    hasher.update(&salted);
    let salted_sha = hasher.finalize().to_vec();
    let salted_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &salted_sha.to_vec());

    let kgx = BigInt::from_bytes_be(num_bigint::Sign::Plus, server_public_key)
        - BigInt::from_bytes_be(num_bigint::Sign::Plus, &k)
            * powmod(
                &group_generator.clone(),
                &salted_bigint,
                &group_prime.clone(),
            );

    let pms = powmod(
        &kgx,
        &(BigInt::from_bytes_be(num_bigint::Sign::Plus, client_private_key)
            + BigInt::from_bytes_be(num_bigint::Sign::Plus, &u) * salted_bigint),
        &group_prime.clone(),
    );

    let mut hasher = Sha256::new();
    hasher.update(pms.to_bytes_be().1);
    hasher.finalize().to_vec()
}

pub fn modm(a: &BigInt, b: &BigInt) -> BigInt {
    let mut result = a % b;
    if result.sign() == Sign::Minus {
        result += b;
    }
    result
}

pub fn powmod(g: &BigInt, x: &BigInt, n: &BigInt) -> BigInt {
    fn _powermod(g: &BigInt, x: &BigInt, n: &BigInt) -> BigInt {
        if *x == BigInt::from(0u32) {
            return BigInt::from(1u32);
        }
        let mut r = _powermod(g, &(x >> 1u32), n);
        r *= r.clone();
        if x & BigInt::from(1u32) == BigInt::from(1u32) {
            r *= g;
        }
        modm(&r, n)
    }

    _powermod(g, x, n)
}

pub fn compute_m(
    username: &String,
    salt: &Vec<u8>,
    client_public_key: &Vec<u8>,
    server_public_key: &Vec<u8>,
    shared_key: &Vec<u8>,
) -> Vec<u8> {
    let group_prime = BigInt::from_str_radix( r#"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"#, 16).unwrap();
    let group_generator = BigInt::from_bytes_be(num_bigint::Sign::Plus, &[5]);

    let mut hasher = Sha256::new();
    hasher.update(group_prime.to_bytes_be().1);
    let n = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    let padded_generator = pad(group_generator.to_bytes_be().1.as_slice(), 3072 >> 3);
    hasher.update(&padded_generator);
    let g = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(username);
    let i = hasher.finalize().to_vec();

    let xor_ng: Vec<u8> = n.iter().enumerate().map(|(idx, b)| b ^ g[idx]).collect();

    let mut final_data = Vec::new();
    final_data.extend_from_slice(&xor_ng);
    final_data.extend_from_slice(i.as_slice());
    final_data.extend_from_slice(salt.as_slice());
    final_data.extend_from_slice(client_public_key.as_slice());
    final_data.extend_from_slice(server_public_key.as_slice());
    final_data.extend_from_slice(shared_key.as_slice());

    let mut hasher = Sha256::new();
    hasher.update(&final_data);
    let final_hash = hasher.finalize();
    final_hash.to_vec()
}
