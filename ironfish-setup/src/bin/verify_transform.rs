extern crate phase2;
extern crate pairing;
extern crate blake2_rfc;

use std::fs::File;
use std::io::BufReader;
use blake2_rfc::blake2b::Blake2b;

fn main() {
    let params = File::open("params").unwrap();
    let mut params = BufReader::with_capacity(1024 * 1024, params);

    let new_params = File::open("new_params").unwrap();
    let mut new_params = BufReader::with_capacity(1024 * 1024, new_params);

    println!("reading spend");
    let new_ironfish_zkp_spend = phase2::MPCParameters::read(&mut new_params, true)
        .expect("couldn't deserialize Sapling Spend new_params");

    println!("reading output");
    let new_ironfish_zkp_output = phase2::MPCParameters::read(&mut new_params, true)
        .expect("couldn't deserialize Sapling Output new_params");

    println!("reading mint");
    let new_ironfish_zkp_mint_asset = phase2::MPCParameters::read(&mut new_params, true)
        .expect("couldn't deserialize Sprout JoinSplit new_params");

    let ironfish_zkp_spend = phase2::MPCParameters::read(&mut params, false)
        .expect("couldn't deserialize Sapling Spend params");

    let ironfish_zkp_output = phase2::MPCParameters::read(&mut params, false)
        .expect("couldn't deserialize Sapling Output params");

    let ironfish_zkp_mint_asset = phase2::MPCParameters::read(&mut params, false)
        .expect("couldn't deserialize Sprout JoinSplit params");

    let h1 = match phase2::verify_contribution(&ironfish_zkp_spend, &new_ironfish_zkp_spend) {
        Ok(hash) => hash,
        Err(_) => panic!("invalid transformation!")
    };

    let h2 = match phase2::verify_contribution(&ironfish_zkp_output, &new_ironfish_zkp_output) {
        Ok(hash) => hash,
        Err(_) => panic!("invalid transformation!")
    };

    let h3 = match phase2::verify_contribution(&ironfish_zkp_mint_asset, &new_ironfish_zkp_mint_asset) {
        Ok(hash) => hash,
        Err(_) => panic!("invalid transformation!")
    };

    let mut h = Blake2b::new(64);
    h.update(&h1);
    h.update(&h2);
    h.update(&h3);
    let h = h.finalize();

    println!("{}", into_hex(h.as_ref()));
}

fn into_hex(h: &[u8]) -> String {
    let mut f = String::new();

    for byte in &h[..] {
        f += &format!("{:02x}", byte);
    }

    f
}
